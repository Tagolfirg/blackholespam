/* regexip.c */
static char *id = 
     "$Id: regexip.c,v 1.17 2002/08/08 20:08:07 bitbytebit Exp $";
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
#include <ctype.h>
#include "my_string.h"
#include "max.h"

#ifndef USE_MCONFIG
#include "config.h"
#endif

extern int DEBUG;
extern int checkreverse;

int regexip(char *line, char *iprelay, char *hostrelay)
{
  int i, j, x = 0, inside = 0;
  int a, b, c, d;

  if(checkreverse > 0) {
    /* get supposid hostname */
    for(i = 15, j = 0; line[i] != ' ' && line[i] != '\0'; i++, j++)
      hostrelay[j] = line[i];
    hostrelay[j] = '\0';
    j = 0;
  } else
    i = j = 0;

  /* Regexp to get IP Address into iprelay string */
  for(; line[i] != '\0'; i++) {
    if(line[i] == '(' || line[i] == '[' || line[i] == '@') {
      /* Start of IP Address */
      if(line[i + 1] != '\0' && isdigit(line[i + 1])) {
        inside = 1;
        x = j = 0;
      }
    } else if(inside > 0 && inside <= 3) {
      /* Inside a number portion of IP Address */
      if(!isdigit(line[i])) {
        inside = 0;
        x = 0;
      } else {
        /* A Dot is Next */
        if(x >= MAX_RELAY_SIZE)
          break;
        iprelay[x] = line[i];
        strsize = x;
        x++;
        inside++;
        if(line[i + 1] == '.') {
          if(j >= MAX_RELAY_SIZE || j++ >= 3)
            break;
          iprelay[x] = '.';
          strsize = x;
          x++;
          i++;
          inside = 1;
        }
      }
    }
  }
  iprelay[strsize+1] = '\0';

  if(j != 3 || sscanf(iprelay, "%d.%d.%d.%d", &a, &b, &c, &d) != 4 ||
     a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 ||
     d < 0 || d > 255) {
    return (1);
  }


  if(!iprelay) {
    return (1);
  } else {
    if(my_strlen(iprelay) < 16) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        fprintf(stderr, "Found Relay IP: %s Host: %s\n", iprelay, hostrelay);
      }
#endif
      return (0);
    }
    iprelay[0] = '\0';
  }
  return (1);
}

