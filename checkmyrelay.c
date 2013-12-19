/* checkmyrelay.c */
static char *id = 
     "$Id: checkmyrelay.c,v 1.13 2002/08/08 20:08:07 bitbytebit Exp $";
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
#include <string.h>

#ifndef USE_MCONFIG
#include "config.h"
#endif

int ipcalc(char *, char *);

extern int DEBUG;

int checkmyrelay(char *iprelay, char *myrelays[])
{
  int i;

  /* Check if Relay is one of our own */
  for(i = 0; myrelays[i] != NULL; i++) {
    if(ipcalc(iprelay, myrelays[i]) == 1) {
#if WITH_DEBUG == 1
      if(DEBUG)
        fprintf(stderr,
                "  Match My Relay (%d) %s, continuing...\n", i, iprelay);
#endif
      /* Matched */
      return (0);
    }
  }

  /* No Match */
  return (1);
}

