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
 * Abstractions of getprotoent_r() to avoid polluting other source files
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


int ares_getprotobynumber_r(const char *protoname, char *buf, size_t bufsize, struct servent **pent)
{
#ifdef GETPROTOBYNUMBER_R
	struct protoent *pe = (struct protoent*) buf;

	return getprotobynumber_r(protoname, pe, (char*) (pe + 1), bufsize - sizeof(*pe), pent);
#else
	/* Just hope this is thread-safe. Nothing else we can do. */
	*pent = getprotobynumber(protoname);

	return (*pent ? 0 : ERRNO);
#endif
}
