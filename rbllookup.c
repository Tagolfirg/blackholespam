/* rbllookup.c */
static char *id = 
     "$Id: rbllookup.c,v 1.21 2002/08/16 16:22:35 bitbytebit Exp $";
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

#ifndef USE_MCONFIG
#include "config.h"
#endif

int rblcheck(int, int, int, int, char *);

extern int DEBUG;
extern int STOP_WHEN_FOUND;
extern int level;
extern char *log_info;

int rbllookup(char *iprelay, char *rblhosts[])
{
  int a, b, c, d;
  int rblfiltered = 0;
  int response = 0;
  int i;

  /* Check for Valid IP Address */
  if(sscanf(iprelay, "%d.%d.%d.%d", &a, &b, &c, &d) != 4 ||
     a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 ||
     d < 0 || d > 255) {
    return 0;
  }

  /* Go through RBL Hosts,  */
  for(i = 0; rblhosts[i] != NULL; i++) {
#if WITH_DEBUG == 1
    if(DEBUG)
      fprintf(stderr, " (%d.) %-25s", i, rblhosts[i]);
#endif

    response = rblcheck(a, b, c, d, rblhosts[i]);
    if(response == 1) {
      rblfiltered++;

      if(STOP_WHEN_FOUND > 0) {
        strsize = my_strlen(rblhosts[i]) + typlen(int) + 9;
        log_info = malloc(strsize + 1);
        if(log_info == NULL)
          return 1;

        snprintf(log_info, strsize + 1,
                 "(level %d) %s", i, rblhosts[i]);
        log_info[strsize] = (char)'\0';

        if(DEBUG)
          fprintf(stderr, " Match RBL %s\n", log_info);

        return 1;
      }
    }
#if WITH_DEBUG == 1
    else if(DEBUG)
      fprintf(stderr, "\n");
#endif

    if(i >= level && STOP_WHEN_FOUND > 0)
      break;

    if(STOP_WHEN_FOUND < 1) {
      if(rblfiltered >= level) {
        strsize = my_strlen(rblhosts[i]) + typlen(int) + 9;
        log_info = malloc(strsize + 1);
        if(log_info == NULL)
          return 1;

        snprintf(log_info, strsize + 1,
                 "(level %d) %s", i, rblhosts[i]);
        log_info[strsize] = (char)'\0';

        if(DEBUG)
          fprintf(stderr, " %s\n", log_info);

        return 1;
      }
    }
  }
  return 0;
}

