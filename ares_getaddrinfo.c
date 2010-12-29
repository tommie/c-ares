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
#define ARE_ANY_BITS_SET(x, mask) ((x) & (mask))
#define ARE_BITS_SET(x, mask) (((x) & (mask)) == (mask))
#define CLEAR_BITS(x, mask) ((x) &= ~(mask))

/* Bit masks for ares_gaicb.ar_state */
#define ARES_GAICB_SERV               (1u << 0u) /* The service must be looked up */
#define ARES_GAICB_NUMERIC_SERV       (1u << 1u) /* The service may be a numeric port */
#define ARES_GAICB_HOST_INET          (1u << 2u) /* The AF_INET address must be looked up */
#define ARES_GAICB_NUMERIC_HOST_INET  (1u << 3u) /* The host name may be a numeric AF_INET address */
#define ARES_GAICB_NUMERIC_HOST_INET6 (1u << 4u) /* The host name may be a numeric AF_INET6 address */
#define ARES_GAICB_CANONICAL          (1u << 5u) /* The canonical name must be looked up */
#define ARES_GAICB_HOST_INET6         (1u << 6u) /* The AF_INET6 address must be looked up */

#define ARES_GAICB_ANY_HOST (ARES_GAICB_HOST_INET | ARES_GAICB_HOST_INET6 | ARES_GAICB_NUMERIC_HOST_INET | ARES_GAICB_NUMERIC_HOST_INET6)


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
 * Construct a new ares_addrinfo object and assign it the given
 * AF_INET address.
 *
 * The sockaddr_in.sin_port member is set to zero.
 *
 * @param template the template addrinfo object to copy.
 * @param addr the address to fill in.
 * @return a malloc()d object, suitable for ares_freeaddrinfo(),
 *         or NULL on error.
**/
static struct ares_addrinfo* create_addrinfo_inet(const struct ares_addrinfo *template, const struct in_addr *addr)
{
	struct sockaddr_in *sa;
	struct ares_addrinfo *result = malloc(sizeof(*result) + sizeof(*sa));

	if (!result) return NULL;

	*result = *template;
	result->ai_family = AF_INET;
	result->ai_addrlen = sizeof(*sa);
	result->ai_addr = (struct sockaddr*) (result + 1);

	sa = (struct sockaddr_in*) result->ai_addr;

	memset(sa, 0, sizeof(*sa));
	sa->sin_family = AF_INET;
	sa->sin_addr = *addr;

	return result;
}

/**
 * Construct a new ares_addrinfo object and assign it the given
 * AF_INET6 address.
 *
 * The sockaddr_in6.sin6_port member is set to zero.
 *
 * @param template the template addrinfo object to copy.
 * @param addr the address to fill in.
 * @return a malloc()d object, suitable for ares_freeaddrinfo(),
 *         or NULL on error.
**/
static struct ares_addrinfo* create_addrinfo_inet6(const struct ares_addrinfo *template, const struct in6_addr *addr)
{
	struct sockaddr_in6 *sa;
	struct ares_addrinfo *result = malloc(sizeof(*result) + sizeof(*sa));

	if (!result) return NULL;

	*result = *template;
	result->ai_family = AF_INET6;
	result->ai_addrlen = sizeof(*sa);
	result->ai_addr = (struct sockaddr*) (result + 1);

	sa = (struct sockaddr_in6*) result->ai_addr;

	memset(sa, 0, sizeof(*sa));
	sa->sin6_family = AF_INET6;
	sa->sin6_addr = *addr;

	return result;
}

/**
 * Free the given ares_addrinfo object and it's members.
 *
 * Each object is free()d.
**/
static void ares_freeaddrinfo(struct ares_addrinfo *ai)
{
	while (ai) {
		struct ares_addrinfo *next = ai->ai_next;

		free(ai->ai_canonname);
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
	result = create_addrinfo_inet(&cb->ar_hints, &addr);

	if (!result) {
		cb->ar_callback(cb->ar_arg, ARES_ENOMEM, 0, NULL);
		free_gaicb(cb);
		return;
	}

	/* Add to the result linked list. */
	result->ai_next = cb->ar_result;
	cb->ar_result = result;

	if (ARE_BITS_SET(cb->ar_hints.ai_flags, ARES_AI_CANONNAME)) {
		/* glibc 2.7 returns the literal address in this case.
		 * So do we.
		 */
		result->ai_canonname = strdup(cb->ar_node);

		if (!result->ai_canonname) {
			cb->ar_callback(cb->ar_arg, ARES_ENOMEM, 0, NULL);
			free_gaicb(cb);
			return;
		}
	}

	CLEAR_BITS(cb->ar_state, ARES_GAICB_HOST_INET | ARES_GAICB_HOST_INET6);
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
	result = create_addrinfo_inet6(&cb->ar_hints, &addr);

	if (!result) {
		cb->ar_callback(cb->ar_arg, ARES_ENOMEM, 0, NULL);
		free_gaicb(cb);
		return;
	}

	/* Add to the result linked list. */
	result->ai_next = cb->ar_result;
	cb->ar_result = result;

	if (ARE_BITS_SET(cb->ar_hints.ai_flags, ARES_AI_CANONNAME)) {
		/* glibc 2.7 returns the literal address in this case.
		 * So do we.
		 */
		result->ai_canonname = strdup(cb->ar_node);

		if (!result->ai_canonname) {
			cb->ar_callback(cb->ar_arg, ARES_ENOMEM, 0, NULL);
			free_gaicb(cb);
			return;
		}
	}

	CLEAR_BITS(cb->ar_state, ARES_GAICB_HOST_INET | ARES_GAICB_HOST_INET6);
	next_state(cb);
}

/**
 * Callback for all resolve_host_*() functions.
 *
 * Populates the ares_gaicb.ar_result with node information,
 * and calls next_state() on success.
 *
 * @param arg the ares_gaicb object.
**/
static void host_callback(void *arg, int status, int timeouts, struct hostent *hostent)
{
	struct ares_gaicb *cb = arg;
	char **addr;

	cb->ar_timeouts += timeouts;

	if (status != ARES_SUCCESS) {
		if (ARE_ANY_BITS_SET(cb->ar_state, ARES_GAICB_ANY_HOST)) {
			/* There is still a possibility of getting a host lookup. */
			next_state(cb);
			return;
		}

		/* This was the last attempt. Fail. */
		cb->ar_callback(cb->ar_arg, status, cb->ar_timeouts, NULL);
		free_gaicb(cb);
		return;
	}

	switch (hostent->h_addrtype) {
	case AF_INET:
		for (addr = hostent->h_addr_list; *addr; ++addr) {
			struct ares_addrinfo *result = create_addrinfo_inet(&cb->ar_hints, (struct in_addr*) *addr);

			if (!result) {
				cb->ar_callback(cb->ar_arg, ARES_ENOMEM, cb->ar_timeouts, NULL);
				free_gaicb(cb);
				return;
			}

			/* Add to result list. */
			result->ai_next = cb->ar_result;
			cb->ar_result = result;
		}

		/* Since ares_gethostbyname() returns AF_INET addresses
		 * even for AF_INET6 queries, we may end up in this case
		 * when we asked for AF_INET6, so there is no reason for us
		 * to query AF_INET specifically.
		 */
		CLEAR_BITS(cb->ar_state, ARES_GAICB_HOST_INET);
		break;

	case AF_INET6:
		for (addr = hostent->h_addr_list; *addr; ++addr) {
			struct ares_addrinfo *result = create_addrinfo_inet6(&cb->ar_hints, (struct in6_addr*) *addr);

			if (!result) {
				cb->ar_callback(cb->ar_arg, ARES_ENOMEM, cb->ar_timeouts, NULL);
				free_gaicb(cb);
				return;
			}

			/* Add to result list. */
			result->ai_next = cb->ar_result;
			cb->ar_result = result;
		}

		/* For symmetry with the above. */
		CLEAR_BITS(cb->ar_state, ARES_GAICB_HOST_INET6);
		break;
	}

	if (ARE_BITS_SET(cb->ar_state, ARES_GAICB_CANONICAL) && hostent->h_name) {
		/* If we need the canonical name, and one is available,
		 * add it, since it's free.
		 */
		cb->ar_result->ai_canonname = strdup(hostent->h_name);

		if (!cb->ar_result->ai_canonname) {
			cb->ar_callback(cb->ar_arg, ARES_ENOMEM, cb->ar_timeouts, NULL);
			free_gaicb(cb);
			return;
		}
	}

	next_state(cb);
}

/**
 * Attempt to resolve the node name of the request.
 *
 * We are reasonably certain the node is a real domain name.
**/
static void resolve_host_inet(struct ares_gaicb *cb)
{
	ares_gethostbyname(cb->ar_channel, cb->ar_node, AF_INET, host_callback, cb);
}

/**
 * Attempt to resolve the node name of the request.
 *
 * We are reasonably certain the node is a real domain name.
**/
static void resolve_host_inet6(struct ares_gaicb *cb)
{
	ares_gethostbyname(cb->ar_channel, cb->ar_node, AF_INET6, host_callback, cb);
}

/**
 * Retrieve the canonical name.
 *
 * If one is already set for any result object, use that.
 * Else, fail.
**/
static void find_canonical(struct ares_gaicb *cb)
{
	struct ares_addrinfo *ai;

	if (cb->ar_result && cb->ar_result->ai_canonname) {
		/* We already have the canonical name in place. */
		next_state(cb);
		return;
	}

	/* Look for the canonical name in some trailing addrinfo object. */
	for (ai = cb->ar_result; ai; ai = ai->ai_next) {
		if (ai != cb->ar_result && ai->ai_canonname) {
			cb->ar_result->ai_canonname = strdup(ai->ai_canonname);

			if (!cb->ar_result->ai_canonname) {
				cb->ar_callback(cb->ar_arg, ARES_ENOMEM, cb->ar_timeouts, NULL);
				free_gaicb(cb);
				return;
			}

			next_state(cb);
			return;
		}
	}

	/* TODO(tommie): Is there any case where we will actually get here?
	 *               Should we do a reverse lookup then?
	 */

	/* Failed to get canonical name. */
	cb->ar_callback(cb->ar_arg, ARES_EBADNAME, cb->ar_timeouts, NULL);
	free_gaicb(cb);
}

/**
 * Attempt to resolve the ar_service member as a number.
**/
static void try_serv_strtol(struct ares_gaicb *cb)
{
	long val;
	char *endp;
	struct ares_addrinfo *ai;

	val = strtol(cb->ar_service, &endp, 10);

	if (endp != cb->ar_service + strlen(cb->ar_service)) {
		/* Not a numeric port. */
		next_state(cb);
		return;
	}

	for (ai = cb->ar_result; ai; ai = ai->ai_next) {
		/* TODO(tommie): Are overflow checks necessary here? */
		switch (ai->ai_family) {
		case AF_INET:
			((struct sockaddr_in*) ai->ai_addr)->sin_port = htons(val);
			break;

		case AF_INET6:
			((struct sockaddr_in6*) ai->ai_addr)->sin6_port = htons(val);
			break;

		default:
			/* Should not happen unless our own code is bad. */
			cb->ar_callback(cb->ar_arg, ARES_EBADFAMILY, cb->ar_timeouts, NULL);
			free_gaicb(cb);
			return;
		}
	}

	/* No need to look up service. */
	CLEAR_BITS(cb->ar_state, ARES_GAICB_SERV);
	next_state(cb);
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
	fprintf(stderr, "next_state(cb %p[state 0x%08X])\n", (void*) cb, cb->ar_state);

	/* We always start out doing the host lookup. This way we know which
	 * sockaddrs we will have when we do the service lookup.
	 * Also, this has to be done before the canonical name lookup.
	 */
	if (ARE_BITS_SET(cb->ar_state, ARES_GAICB_NUMERIC_HOST_INET6)) {
		CLEAR_BITS(cb->ar_state, ARES_GAICB_NUMERIC_HOST_INET6);
		try_pton_inet6(cb);
		return;
	}

	if (ARE_BITS_SET(cb->ar_state, ARES_GAICB_NUMERIC_HOST_INET)) {
		CLEAR_BITS(cb->ar_state, ARES_GAICB_NUMERIC_HOST_INET);
		try_pton_inet(cb);
		return;
	}

	if (ARE_ANY_BITS_SET(cb->ar_state, ARES_GAICB_ANY_HOST) && ARE_BITS_SET(cb->ar_hints.ai_flags, ARES_AI_NUMERICHOST)) {
		/* We are not allowed to use DNS, but haven't been able to
		 * resolve the node name.
		 */
		cb->ar_callback(cb->ar_arg, ARES_ENONAME, 0, NULL);
		free_gaicb(cb);
		return;
	}

	if (ARE_BITS_SET(cb->ar_state, ARES_GAICB_HOST_INET6)) {
		CLEAR_BITS(cb->ar_state, ARES_GAICB_HOST_INET6);
		resolve_host_inet6(cb);
		return;
	}

	if (ARE_BITS_SET(cb->ar_state, ARES_GAICB_HOST_INET)) {
		CLEAR_BITS(cb->ar_state, ARES_GAICB_HOST_INET);
		resolve_host_inet(cb);
		return;
	}

	if (ARE_BITS_SET(cb->ar_state, ARES_GAICB_CANONICAL)) {
		CLEAR_BITS(cb->ar_state, ARES_GAICB_CANONICAL);
		find_canonical(cb);
		return;
	}

	if (ARE_BITS_SET(cb->ar_state, ARES_GAICB_NUMERIC_SERV)) {
		CLEAR_BITS(cb->ar_state, ARES_GAICB_NUMERIC_SERV);
		try_serv_strtol(cb);
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
		(nodename && (hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET) ? ARES_GAICB_HOST_INET : 0) |
		(nodename && (hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET6) ? ARES_GAICB_HOST_INET6 : 0) |
		(hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET ? ARES_GAICB_NUMERIC_HOST_INET : 0) |
		(hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET6 ? ARES_GAICB_NUMERIC_HOST_INET6 : 0) |
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
