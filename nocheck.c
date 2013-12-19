/* nocheck.c */
static char *id = 
     "$Id: nocheck.c,v 1.5 2002/08/08 20:08:07 bitbytebit Exp $";
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
#include "my_string.h"

#define USER_AT_DOMAIN 	1
#define BARE_DOMAIN     2
#define AT_DOMAIN  	3
#define DOT_DOMAIN 	4
#define BARE_USER 	5

extern int DEBUG;

int no_check(char *rcptto, char *nocheck[])
{
  int i, j = 0, x = 0;
  int type = 0;

  for(i = 0; nocheck[i] != NULL; i++) {
    /* Figure out filter type */
    if(nocheck[i][0] == '@') {
      type = AT_DOMAIN;
    } else if(nocheck[i][0] == '.') {
      type = DOT_DOMAIN;
    } else if(!strstr(nocheck[i], "@")) {
      type = BARE_DOMAIN;
    } else {
      int b;
      for(b = 0; nocheck[i][b] != '\0' && nocheck[i][b] != '\n'; b++);
      if(nocheck[i][b - 1] == '@')
        type = BARE_USER;
      else
        type = USER_AT_DOMAIN;
    }

    switch (type) {
    case AT_DOMAIN:
      if(strstr(rcptto, "@")) {
        for(j = 0; rcptto[j] != '@'; j++);
        j++;

        for(x = 1; rcptto[j] != '\0'
            && nocheck[i][x] != '\0' && rcptto[j] == nocheck[i][x]; x++, j++);

        if(rcptto[j] == nocheck[i][x]) {
          /* Match @domain.com */
          if(DEBUG) {
            fprintf(stderr, " Checking %s against domain (%d) %s\n",
                    rcptto, i, nocheck[i]);
            fprintf(stderr, "  Match Email @Domain: %s\n", rcptto);
          }
          return (1);
        }
      }
      break;
    case DOT_DOMAIN:
      if(strstr(rcptto, "@")) {
        j = 0;
        while(rcptto[j] != '\0' && nocheck[i][x] != '\0') {
          for(; rcptto[j] != '.' && rcptto[j] != '\0'; j++);
          if(rcptto[j] != '\0')
            j++;

          x = 1;
          for(; rcptto[j] != '\0'
              && nocheck[i][x] != '\0' && rcptto[j] == nocheck[i][x]; x++, j++);

          if(rcptto[j] == nocheck[i][x]
             && rcptto[j] == '\0' && nocheck[i][x] == '\0') {
            /* Match .domain.com */
            if(DEBUG) {
              fprintf(stderr, " Checking %s against domain (%d) %s\n",
                      rcptto, i, nocheck[i]);
              fprintf(stderr, "  Match Email .Domain: %s\n", rcptto);
            }
            return (1);
          }
        }
      }
      break;
    case BARE_DOMAIN:
      if(strstr(rcptto, "@")) {
        for(j = 0; rcptto[j] != '@'; j++);
        j++;

        for(x = 0; rcptto[j] != '\0'
            && nocheck[i][x] != '\0' && rcptto[j] == nocheck[i][x]; x++, j++);

        if(rcptto[j] == nocheck[i][x]) {
          /* Match domain.com */
          if(DEBUG) {
            fprintf(stderr, " Checking %s against domain (%d) %s\n",
                    rcptto, i, nocheck[i]);
            fprintf(stderr, "  Match Email Domain: %s\n", rcptto);
          }
          return (1);
        }
      }
      if(strstr(rcptto, "@")) {
        j = 0;
        while(rcptto[j] != '\0' && nocheck[i][x] != '\0') {
          for(; rcptto[j] != '.' && rcptto[j] != '\0'; j++);
          if(rcptto[j] != '\0')
            j++;

          x = 0;
          for(; rcptto[j] != '\0'
              && nocheck[i][x] != '\0' && rcptto[j] == nocheck[i][x]; x++, j++);

          if(rcptto[j] == nocheck[i][x]
             && rcptto[j] == '\0' && nocheck[i][x] == '\0') {
            /* Match .domain.com */
            if(DEBUG) {
              fprintf(stderr, " Checking %s against domain (%d) %s\n",
                      rcptto, i, nocheck[i]);
              fprintf(stderr, "  Match Email .Domain: %s\n", rcptto);
            }
            return (1);
          }
        }
      }
      break;
    case USER_AT_DOMAIN:
      if(my_strlen(rcptto) == my_strlen(nocheck[i])) {
        if(!strncmp(rcptto, nocheck[i], my_strlen(rcptto))) {
          /* Match me@domain.com */
          if(DEBUG) {
            fprintf(stderr, " Checking %s against address (%d) %s\n",
                    rcptto, i, nocheck[i]);
            fprintf(stderr, "  Match Email Address: %s\n", rcptto);
          }
          return (1);
        }
      }
      break;
    case BARE_USER:
      if(!strncmp(rcptto, nocheck[i], (my_strlen(nocheck[i]) - 2))) {
        /* Match me@ */
        if(DEBUG) {
          fprintf(stderr, " Checking %s against user (%d) %s\n",
                  rcptto, i, nocheck[i]);
          fprintf(stderr, "  Match User: %s\n", rcptto);
        }
        return (1);
      }
      break;
    default:
      break;
    }
  }

  /* Not excluded user */
  return (0);
}
