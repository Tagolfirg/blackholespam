/* zstrncpy.c - Copy a specified number of bytes from string to string */

// 04/03/2002 - Corrected a 1-off situation where if the len was 1, the \0
// 	would be written to undefined space - my own fault on that one.


#include <stddef.h>
#include <syslog.h>
#include <stdio.h>
#include "zstr.h"


/*------------------------------------------------------------------------
 Procedure:     zstrncpy ID:1
 Purpose:       Copy characters from 'src' to 'dst', writing not more than 'len'
                characters to the destination, including the terminating \0.
                Thus, for any effective copying, len must be > 1.
 Input:         char *dst: Destination string
                char *src: Source string
                size_t len: length of string
 Output:        Returns a pointer to the destination string.
 Errors:
------------------------------------------------------------------------*/
char *zstrncpy (char *dst, const char *src, size_t len)
{
	char *dp = dst;
	const char *sp = src;

	if (len == 0) return dst;

	// Compensate for the fact that we have to add a \0 at the end of our buffer
	// no matter WHAT!

//	if (len == sizeof(void *)) syslog(1,"WARNING: Possible pointer size being sent");

	while ((len) && (*sp != '\0'))
	{





















		*dp++ = *sp++;
		len--;
	}

	*dp = '\0';

	return dst;
}


char *zstrncat( char *dst, const char *src, size_t len )
{
	char *dp = dst;
	const char *sp = src;
	int cc;

	if (len == 0) return dst;

	len--;

	// Locate the end of the current string.
	cc = 0;
	while ((*dp)&&(cc < len)) { dp++; cc++; }

	// If we have no more buffer space, then return the destination

	if (cc >= len) return dst;

	// While we have more source, and there's more char space left in the buffer

	while ((*sp)&&(cc < len))
	{
		cc++;
		*dp = *sp;
		dp++;
		sp++;
	}

	// Terminate dst, as a gaurantee of string ending.

	*dp = '\0';

	return dst;
}


char *zstrncate( char *dst, const char *src, size_t len, char *endpoint )
{
	char *dp = dst;
	const char *sp = src;
	int cc = 0;

	if (len == 0) return dst;

	len--;

	// If endpoint does not relate correctly, then force manual detection
	// of the endpoint.

	if ((!endpoint)||(endpoint == dst)||((endpoint -dst +1)>len))
	{
		// Locate the end of the current string.
		cc = 0;
		while ((*dp != '\0')&&(cc < len)) { dp++; cc++; }
	}
	else {
		cc = endpoint -dst +1;
		dp = endpoint;
	}

	// If we have no more buffer space, then return the destination

	if (cc >= len) return dst;

	// While we have more source, and there's more char space left in the buffer

	while ((*sp)&&(cc < len))
	{
		cc++;
		*dp = *sp;
		dp++;
		sp++;
	}

	// Terminate dst, as a gaurantee of string ending.

	*dp = '\0';

	return dst;
}



