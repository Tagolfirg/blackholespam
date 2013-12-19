/* checkbadrelay.c */
static char *id = 
     "$Id: checkbadrelay.c,v 1.19 2002/08/16 16:22:35 bitbytebit Exp $";
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
#include "my_string.h"
#include "max.h"

int ipcalc(char *, char *);

extern int DEBUG;
extern char *log_info;

int checkbadrelay(char *iprelay, char *badrelays[])
{
  int i;

  /* Check if Relay is a bad relay */
  for(i = 0; badrelays[i] != NULL; i++) {
    if(ipcalc(iprelay, badrelays[i]) == 1) {
      strsize = (my_strlen(iprelay) + my_strlen(badrelays[i]) + 9);
      log_info = malloc(strsize + 1);
      if(log_info == NULL)
        return (1);

      snprintf(log_info, strsize + 1, "(relay %s) %s", iprelay,  badrelays[i]);

      if(DEBUG)
        fprintf(stderr, " Match Bad Relay %s\n", log_info);

      return (1);
    }
  }

  /* Not on bad relays */
  return (0);
}
