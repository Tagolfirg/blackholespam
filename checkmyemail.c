/* checkmyemail.c */
static char *id = 
     "$Id: checkmyemail.c,v 1.15 2002/08/16 16:22:35 bitbytebit Exp $";
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
#include "max.h"

#define USER_AT_DOMAIN 	1
#define BARE_DOMAIN     2
#define AT_DOMAIN  	3
#define DOT_DOMAIN 	4

extern int DEBUG;
extern char *mailfrom;
extern char *log_info;

int checkmyemail(char *rcptto, char *myemail[])
{
  int i, j = 0, x = 0;
  int type = 0;

  if(rcptto == NULL)
    return 1;

  for(i = 0; myemail[i] != NULL; i++) {
    /* Figure out filter type */
    if(myemail[i][0] == '@') {
      type = AT_DOMAIN;
    } else if(myemail[i][0] == '.') {
      type = DOT_DOMAIN;
    } else if(!strstr(myemail[i], "@")) {
      type = BARE_DOMAIN;
    } else {
      type = USER_AT_DOMAIN;
    }

    switch (type) {
    case AT_DOMAIN:
      if(strstr(rcptto, "@")) {
        for(j = 0; rcptto[j] != '@'; j++);
        j++;

        for(x = 1; rcptto[j] != '\0'
            && myemail[i][x] != '\0' && rcptto[j] == myemail[i][x]; x++, j++);

        if(rcptto[j] == myemail[i][x]) {
          /* Match @domain.com */
          if(DEBUG) {
            fprintf(stderr, " Checking %s against domain (%d) %s\n",
                    rcptto, i, myemail[i]);
            fprintf(stderr, "  Match MY Email @Domain: %s\n", rcptto);
          }
          return 1;
        }
      }
      break;
    case DOT_DOMAIN:
      if(strstr(rcptto, "@")) {
        j = 0;
        while(rcptto[j] != '\0' && myemail[i][x] != '\0') {
          for(; rcptto[j] != '.' && rcptto[j] != '\0'; j++);
          if(rcptto[j] != '\0')
            j++;

          x = 1;
          for(; rcptto[j] != '\0'
              && myemail[i][x] != '\0' && rcptto[j] == myemail[i][x]; x++, j++);

          if(rcptto[j] == myemail[i][x]
             && rcptto[j] == '\0' && myemail[i][x] == '\0') {
            /* Match .domain.com */
            if(DEBUG) {
              fprintf(stderr, " Checking %s against domain (%d) %s\n",
                      rcptto, i, myemail[i]);
              fprintf(stderr, "  Match MY Email .Domain: %s\n", rcptto);
            }
            return 1;
          }
        }
      }
      break;
    case BARE_DOMAIN:
      if(strstr(rcptto, "@")) {
        for(j = 0; rcptto[j] != '@'; j++);
        j++;

        for(x = 0; rcptto[j] != '\0'
            && myemail[i][x] != '\0' && rcptto[j] == myemail[i][x]; x++, j++);

        if(rcptto[j] == myemail[i][x]) {
          /* Match domain.com */
          if(DEBUG) {
            fprintf(stderr, " Checking %s against domain (%d) %s\n",
                    rcptto, i, myemail[i]);
            fprintf(stderr, "  Match MY Email Domain: %s\n", rcptto);
          }
          return 1;
        }
      }
      if(strstr(rcptto, "@")) {
        j = 0;
        while(rcptto[j] != '\0' && myemail[i][x] != '\0') {
          for(; rcptto[j] != '.' && rcptto[j] != '\0'; j++);
          if(rcptto[j] != '\0')
            j++;

          x = 0;
          for(; rcptto[j] != '\0'
              && myemail[i][x] != '\0' && rcptto[j] == myemail[i][x]; x++, j++);

          if(rcptto[j] == myemail[i][x]
             && rcptto[j] == '\0' && myemail[i][x] == '\0') {
            /* Match .domain.com */
            if(DEBUG) {
              fprintf(stderr, " Checking %s against domain (%d) %s\n",
                      rcptto, i, myemail[i]);
              fprintf(stderr, "  Match MY Email .Domain: %s\n", rcptto);
            }
            return 1;
          }
        }
      }
      break;
    case USER_AT_DOMAIN:
      if(my_strlen(rcptto) == my_strlen(myemail[i])) {
        if(!strncmp(rcptto, myemail[i], my_strlen(rcptto))) {
          /* Match me@domain.com */
          if(DEBUG) {
            fprintf(stderr, " Checking %s against address (%d) %s\n",
                    rcptto, i, myemail[i]);
            fprintf(stderr, "  Match MY Email Address: %s\n", rcptto);
          }
          return 1;
        }
      }
      break;
    default:
      break;
    }
  }

  /* Not on good rcpt to list */
  strsize = (my_strlen(mailfrom) + my_strlen(myemail[i]) + 3);
  log_info = malloc(strsize + 1);
  if(log_info == NULL)
    return (1);

  snprintf(log_info, strsize + 1, "(%s) %s", mailfrom, myemail[i]);

  if(DEBUG)
    fprintf(stderr, " Match Bad Rcptto %s\n", log_info);

  return 0;
}
