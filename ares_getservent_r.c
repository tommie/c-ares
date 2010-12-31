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
/*
 * Abstractions of getservent_r() to avoid polluting other source files
 * with OS-specific interface glue.
 */

#include "ares_setup.h"
#ifdef HAVE_ERRNO_H
#	include <errno.h>
#endif
#ifdef HAVE_NETDB_H
#	include <netdb.h>
#endif
#include "ares.h"


int ares_getservbyname_r(const char *servicename, const char *protoname, char *buf, size_t bufsize, struct servent **pent)
{
#ifdef HAVE_GETSERVBYNAME_R
	struct servent *se = (struct servent*) buf;

	return getservbyname_r(servicename, protoname, se, (char*) (se + 1), bufsize - sizeof(*se), pent);
#else
	/* Just hope this is thread-safe. Nothing else we can do. */
	*pent = getservbyname(servicename, protoname);

	return (*pent ? 0 : ERRNO);
#endif
}
