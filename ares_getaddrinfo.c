/* Copyright 2010 by Tommie Gannert
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */
#include "ares_setup.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "ares.h"
#include "inet_net_pton.h"


/* --- Macros --- */
#define ARE_BITS_SET(x, mask) (((x) & (mask)) == (mask))
#define CLEAR_BITS(x, mask) ((x) &= ~(mask))

/* Bit masks for ares_gaicb.ar_state */
#define ARES_GAICB_SERV               (1u << 0u) /* The service must be looked up */
#define ARES_GAICB_NUMERIC_SERV       (1u << 1u) /* The service may be a numeric port */
#define ARES_GAICB_HOST               (1u << 2u) /* The host address must be looked up */
#define ARES_GAICB_NUMERIC_HOST_INET  (1u << 3u) /* The host name may be a numeric AF_INET address */
#define ARES_GAICB_NUMERIC_HOST_INET6 (1u << 4u) /* The host name may be a numeric AF_INET6 address */
#define ARES_GAICB_CANONICAL          (1u << 5u) /* The canonical name must be looked up */


/* --- Types --- */
struct ares_gaicb {
	/* Arguments */
	ares_channel ar_channel;
	char *ar_node;
	char *ar_service;
	struct ares_addrinfo ar_hints;
	struct ares_addrinfo *ar_result;
	ares_addrinfo_callback ar_callback;
	void *ar_arg;

	/* State data */
	unsigned int ar_state;
	int ar_status;
	unsigned int ar_timeouts;
};


/* --- Functions --- */
static void next_state(struct ares_gaicb *cb);


/* --- Data --- */
/**
 * Hints used when the hints argument to ares_getaddrinfo() is NULL.
**/
const struct ares_addrinfo DEFAULT_HINTS = {
	/* ai_flags */     ARES_AI_DEFAULT,
	/* ai_family */    AF_UNSPEC,
	/* ai_socktype */  0,
	/* ai_protocol */  0,
	/* ai_addrlen */   0,
	/* ai_canonname */ NULL,
	/* ai_addr */      NULL,
	/* ai_next */      NULL
};


/**
 * Free the given ares_addrinfo object and it's members.
 *
 * Each object is free()d.
**/
static void ares_freeaddrinfo(struct ares_addrinfo *ai)
{
	while (ai) {
		struct ares_addrinfo *next = ai->ai_next;

		free(ai);
		ai = next;
	}
}

/**
 * Free the given gaicb object and it's members.
 *
 * The node, service and result members are free()d.
**/
static void free_gaicb(struct ares_gaicb *cb)
{
	ares_freeaddrinfo(cb->ar_result);
	free(cb->ar_service);
	free(cb->ar_node);
	free(cb);
}

/**
 * Try to convert the name without using DNS as an IPv4 address.
 *
 * Creates and adds an ares_addrinfo object if needed, and
 * calls next_state() when done.
**/
static void try_pton_inet(struct ares_gaicb *cb)
{
	struct in_addr addr;
	struct ares_addrinfo *result;
	struct sockaddr_in *sa;

	if (!cb->ar_node) {
		if (ARE_BITS_SET(cb->ar_hints.ai_flags, ARES_AI_PASSIVE))
			addr.s_addr = htonl(INADDR_ANY);
		else
			addr.s_addr = htonl(INADDR_LOOPBACK);
	} else if (ares_inet_pton(AF_INET, cb->ar_node, &addr) != 1) {
		/* Not a numeric host, so continue. */
		next_state(cb);
		return;
	}

	/* Owned by cb after this function returns. */
	result = malloc(sizeof(*result) + sizeof(*sa));

	if (!result) {
		cb->ar_callback(cb->ar_arg, ARES_ENOMEM, 0, NULL);
		free_gaicb(cb);
		return;
	}

	*result = cb->ar_hints;
	result->ai_family = AF_INET;
	result->ai_addrlen = sizeof(*sa);
	result->ai_addr = result + 1;

	sa = (struct sockaddr_in*) result->ai_addr;

	memset(sa, 0, sizeof(*sa));
	sa->sin_family = AF_INET;
	sa->sin_addr = addr;

	/* Add to the result linked list. */
	result->ai_next = cb->ar_result;
	cb->ar_result = result;

	CLEAR_BITS(cb->ar_state, ARES_GAICB_HOST);
	next_state(cb);
}

/**
 * Try to convert the name without using DNS as an IPv6 address.
 *
 * Creates and adds an ares_addrinfo object if needed, and
 * calls next_state() when done.
**/
static void try_pton_inet6(struct ares_gaicb *cb)
{
	struct in6_addr addr;
	struct ares_addrinfo *result;
	struct sockaddr_in6 *sa;

	if (!cb->ar_node) {
		if (ARE_BITS_SET(cb->ar_hints.ai_flags, ARES_AI_PASSIVE))
			addr = in6addr_any;
		else
			addr = in6addr_loopback;
	} else {
		if (ares_inet_pton(AF_INET6, cb->ar_node, &addr) != 1) {
			/* Not a numeric host, so continue. */
			next_state(cb);
			return;
		}
	}

	/* Owned by cb after this function returns. */
	result = malloc(sizeof(*result));

	if (!result) {
		cb->ar_callback(cb->ar_arg, ARES_ENOMEM, 0, NULL);
		free_gaicb(cb);
		return;
	}

	*result = cb->ar_hints;
	result->ai_family = AF_INET6;
	result->ai_addrlen = sizeof(*sa);
	result->ai_addr = result + 1;

	sa = (struct sockaddr_in6*) result->ai_addr;

	memset(sa, 0, sizeof(*sa));
	sa->sin6_family = AF_INET6;
	sa->sin6_addr = addr;

	/* Add to the result linked list. */
	result->ai_next = cb->ar_result;
	cb->ar_result = result;

	CLEAR_BITS(cb->ar_state, ARES_GAICB_HOST);
	next_state(cb);
}

/**
 * Attempt to resolve the node name of the request.
 *
 * We are reasonably certain the node is a real domain name.
**/
static void resolve_host(struct ares_gaicb *cb)
{
	if (ARE_BITS_SET(cb->ar_hints.ai_flags, ARES_AI_NUMERICHOST)) {
		/* We are not allowed to use DNS. */
		cb->ar_callback(cb->ar_arg, ARES_ENONAME, 0, NULL);
		free_gaicb(cb);
		return;
	}

	/* TODO(tommie): Implement resolution. */

	cb->ar_callback(cb->ar_arg, ARES_ENONAME, 0, NULL);
	free_gaicb(cb);
}

/**
 * Evaluate the state of the request, and perform the next step.
 *
 * The last step is (ares_gaicb.ar_state == 0) and is where the callback
 * is called for success.
 *
 * If there is no state transition defined for a given state,
 * we fail with ARES_EFORMERR for now.
**/
static void next_state(struct ares_gaicb *cb)
{
	/* We always start out doing the host lookup. This way we know which
	 * sockaddrs we will have when we do the service lookup.
	 * Also, this has to be done before the canonical name lookup.
	 */
	if (ARE_BITS_SET(cb->ar_state, ARES_GAICB_NUMERIC_HOST_INET)) {
		CLEAR_BITS(cb->ar_state, ARES_GAICB_NUMERIC_HOST_INET);
		try_pton_inet(cb);
		return;
	}

	if (ARE_BITS_SET(cb->ar_state, ARES_GAICB_NUMERIC_HOST_INET6)) {
		CLEAR_BITS(cb->ar_state, ARES_GAICB_NUMERIC_HOST_INET6);
		try_pton_inet6(cb);
		return;
	}

	if (ARE_BITS_SET(cb->ar_state, ARES_GAICB_HOST)) {
		CLEAR_BITS(cb->ar_state, ARES_GAICB_HOST);
		resolve_host(cb);
		return;
	}

	if (!cb->ar_state) {
		/* The request is done. Call back and clean up. */
		cb->ar_callback(cb->ar_arg, ARES_SUCCESS, cb->ar_timeouts, cb->ar_result);
		free_gaicb(cb);
		return;
	}

	/* We have no transition from this state to something else,
	 * so we just fail.
	 *
	 * TODO(tommie): Error code?
	 */
	cb->ar_callback(cb->ar_arg, ARES_EFORMERR, 0, NULL);
	free_gaicb(cb);
}

/**
 * Start the GAI request.
 *
 * This is a separate function just to isolate the sanity checks in
 * ares_getaddrinfo() from the real work.
 *
 * The parameters are the same as for ares_getaddrinfo().
**/
static void start(ares_channel channel, const char *nodename, const char *servicename, const struct ares_addrinfo *hints, ares_addrinfo_callback callback, void *arg)
{
	struct ares_gaicb *cb = malloc(sizeof(*cb));

	if (!cb) {
		callback(arg, ARES_ENOMEM, 0, NULL);
		return;
	}

	cb->ar_channel = channel;
	cb->ar_node = (nodename ? strdup(nodename) : NULL);
	cb->ar_service = (servicename ? strdup(servicename) : NULL);
	cb->ar_hints = *hints;
	cb->ar_result = NULL;
	cb->ar_callback = callback;
	cb->ar_arg = arg;

	if ((nodename && !cb->ar_node) || (servicename && !cb->ar_service)) {
		/* Failed to allocate node or service name. */
		free_gaicb(cb);
		callback(arg, ARES_ENOMEM, 0, NULL);
		return;
	}

	/* Here, we determine what we have to do. */
	cb->ar_state =
		(servicename ? ARES_GAICB_SERV | ARES_GAICB_NUMERIC_SERV : 0) |
		(nodename ? ARES_GAICB_HOST : 0) |
		(nodename && (hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET) ? ARES_GAICB_NUMERIC_HOST_INET : 0) |
		(nodename && (hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET6) ? ARES_GAICB_NUMERIC_HOST_INET6 : 0) |
		(ARE_BITS_SET(hints->ai_flags, ARES_AI_CANONNAME) ? ARES_GAICB_CANONICAL : 0);

	cb->ar_status = 0;
	cb->ar_timeouts = 0;

	/* Now, we do it. */
	next_state(cb);
}

void ares_getaddrinfo(
	ares_channel channel,
	const char *nodename, const char *servicename,
	const struct ares_addrinfo *hints,
	ares_addrinfo_callback callback, void *arg)
{
	if (!hints) hints = &DEFAULT_HINTS;

	if (!channel) {
		errno = EINVAL;
		callback(arg, ARES_EBADQUERY, 0, NULL);
		return;
	}

	if (!nodename && !servicename) {
		/* At least one must be set. */
		callback(arg, ARES_ENONAME, 0, NULL);
		return;
	}

	if (ARE_BITS_SET(hints->ai_flags, ARES_AI_CANONNAME) && !nodename) {
		/* Cannot determine canonical name without some name. */
		callback(arg, ARES_EBADFLAGS, 0, NULL);
		return;
	}

	if (ARE_BITS_SET(hints->ai_flags, ARES_AI_ALL) && !ARE_BITS_SET(hints->ai_flags, ARES_AI_V4MAPPED)) {
		/* AI_ALL must only be set if AI_V4MAPPED is set. */
		callback(arg, ARES_EBADFLAGS, 0, NULL);
		return;
	}

	if (ARE_BITS_SET(hints->ai_flags, ARES_AI_NUMERICHOST | ARES_AI_CANONNAME)) {
		/* If we may not do any DNS lookups,
		 * we cannot guarantee returning a canonical name.
		 */
		callback(arg, ARES_EBADFLAGS, 0, NULL);
		return;
	}

	/* Check that we can use the given address family. */
	switch (hints->ai_family) {
	case AF_UNSPEC:
	case AF_INET:
	case AF_INET6:
		break;

	default:
		callback(arg, ARES_EBADFAMILY, 0, NULL);
		return;
	}

	start(channel, nodename, servicename, hints, callback, arg);
}
