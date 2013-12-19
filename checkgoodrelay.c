/* checkgoodrelay.c */
static char *id = 
     "$Id: checkgoodrelay.c,v 1.11 2002/08/08 20:08:07 bitbytebit Exp $";
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

int ipcalc(char *, char *);

extern int DEBUG;

int checkgoodrelay(char *iprelay, char *goodrelays[])
{
  int i;

  /* Check if Relay is a good relay */
  for(i = 0; goodrelays[i] != NULL; i++) {
    if(ipcalc(iprelay, goodrelays[i]) == 1) {
      if(DEBUG) {
        fprintf(stderr,
                " Checking: %s against ip %s\n", iprelay, goodrelays[i]);
        fprintf(stderr, " Match Good Relay (%d) %s\n", i, iprelay);
      }
      return (1);
    }
  }

  /* Not on good relays */
  return (0);
}
