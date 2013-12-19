/* string.c */
static char *id=
     "$Id: string.c,v 1.14 2002/08/28 21:18:55 bitbytebit Exp $";
/*
   Copyright (C) 2002
        Chris Kennedy, The Groovy Organization.

   The Blackhole is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Blackhole is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   For a copy of the GNU Library General Public License
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  or go to http://www.gnu.org
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include "max.h"
#include "misc.h"

size_t my_strlcpy(char *, const char *, size_t);
int arraycat(char *[], char *);
void bh_exit(int);

int my_strlen(char *str) {
  /* Return 0 if NULL, and add NULL at end plus cut to MAX_INPUT_LINE */
  if(str == NULL) {
    return 0;
  } else {
    int i;
    for(i=0;i < (MAX_INPUT_LINE+1) && str[i] != '\0';i++);
    /* Resize buffer if too small */
    if(str[i] != '\0') {
#if WITH_DEBUG == 1
      fprintf(stderr, "ERROR: MEMORY BUG, no null at end of string!!!!\n");
      bh_assert(1);
#endif
      str[i] = '\0'; 
    } 
    if(str != NULL)
      return strlen(str);
    else 
      return 0;

    return 0;
  }
}

/* Concatonate an string into an array of strings */
int arraycat(char *array[], char *string) {
  int i, j;
  int incr = 0;
  char *buffer;

  strsize = strlen(string);
  buffer = malloc(strsize + 1);
  if(buffer == NULL)
    return 1;

  for(i=0;array[i] != NULL;i++)
    incr++;

  for(i=0,j=0;i <= strsize;i++) {
    if(string[i] == '\0' || isspace(string[i]) != 0) {
      buffer[j] = '\0';
      array[incr] = malloc(j+1);
      strncpy(array[incr],buffer,j);
      array[incr][j] = '\0';
      incr++;
      j = 0;
      if(string[i] == '\0')
        break;
    } else {
      buffer[j++] = string[i];
    }
  }
  array[incr] = malloc(1);
  array[incr] = '\0';

  return 0;
}

size_t my_strlcpy(char *dst, const char *src, size_t siz)
{
  /*	$OpenBSD: strlcpy.c,v 1.5 2001/05/13 15:40:16 deraadt Exp $	*/
  /*
   * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
   * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
   * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
   * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
   * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
   * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
   * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
   * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
	register char *d = dst;
	register const char *s = src;
	register size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return(s - src - 1);	/* count does not include NUL */
}

size_t my_strlcat(char *dst, const char *src, size_t siz)
{
	register char *d = dst;
	register const char *s = src;
	register size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));	/* count does not include NUL */
}
