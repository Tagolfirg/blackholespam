/* checkdns.c */
static char *id = 
     "$Id: checkgoodemail.c,v 1.14 2002/08/24 18:10:38 bitbytebit Exp $";
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
#define BARE_USER       5

extern int DEBUG;

int checkgoodemail(char *mailfrom, char *goodemail[])
{
  int i, j = 0, x = 0;
  int type = 0;

  for(i = 0; goodemail[i] != NULL; i++) {
    /* Figure out filter type */
    if(goodemail[i][0] == '@') {
      type = AT_DOMAIN;
    } else if(goodemail[i][0] == '.') {
      type = DOT_DOMAIN;
    } else if(!strstr(goodemail[i], "@") && !strstr(goodemail[i], ".")) {
      type = BARE_USER;
    } else if(!strstr(goodemail[i], "@")) {
      type = BARE_DOMAIN;
    } else {
      type = USER_AT_DOMAIN;
    }

    switch (type) {
    case AT_DOMAIN:
      if(strstr(mailfrom, "@")) {
        for(j = 0; mailfrom[j] != '@'; j++);
        j++;

        for(x = 1; mailfrom[j] != '\0'
            && goodemail[i][x] != '\0'
            && mailfrom[j] == goodemail[i][x]; x++, j++);

        if(mailfrom[j] == goodemail[i][x]) {
          /* Match @domain.com */
          if(DEBUG) {
            fprintf(stderr, " Checking %s against domain (%d) %s\n",
                    mailfrom, i, goodemail[i]);
            fprintf(stderr, "  Match GOOD Email @Domain: %s\n", mailfrom);
          }
          return (1);
        }
      }
      break;
    case DOT_DOMAIN:
      if(strstr(mailfrom, "@")) {
        j = 0;
        while(mailfrom[j] != '\0' && goodemail[i][x] != '\0') {
          for(; mailfrom[j] != '.' && mailfrom[j] != '\0'; j++);
          if(mailfrom[j] != '\0')
            j++;

          x = 1;
          for(; mailfrom[j] != '\0'
              && goodemail[i][x] != '\0'
              && mailfrom[j] == goodemail[i][x]; x++, j++);

          if(mailfrom[j] == goodemail[i][x]
             && mailfrom[j] == '\0' && goodemail[i][x] == '\0') {
            /* Match .domain.com */
            if(DEBUG) {
              fprintf(stderr, " Checking %s against domain (%d) %s\n",
                      mailfrom, i, goodemail[i]);
              fprintf(stderr, "  Match GOOD Email .Domain: %s\n", mailfrom);
            }
            return (1);
          }
        }
      }
      break;
    case BARE_USER:
      if(strncmp(mailfrom, goodemail[i], my_strlen(mailfrom)) == 0) {
        if(DEBUG) {
          fprintf(stderr, " Checking %s against domain (%d) %s\n",
               mailfrom, i, goodemail[i]);
          fprintf(stderr, "  Match GOOD Email User: %s\n", mailfrom);
        }
        return (1);
      }
      break;
    case BARE_DOMAIN:
      if(strstr(mailfrom, "@")) {
        for(j = 0; mailfrom[j] != '\0' && mailfrom[j] != '@'; j++);
        j++;

        for(x = 0; mailfrom[j] != '\0'
            && goodemail[i][x] != '\0'
            && mailfrom[j] == goodemail[i][x]; x++, j++);

        if(mailfrom[j] == goodemail[i][x]) {
          /* Match domain.com */
          if(DEBUG) {
            fprintf(stderr, " Checking %s against domain (%d) %s\n",
                    mailfrom, i, goodemail[i]);
            fprintf(stderr, "  Match GOOD Email Domain: %s\n", mailfrom);
          }
          return (1);
        }
      }
      if(strstr(mailfrom, "@")) {
        j = 0;
        while(mailfrom[j] != '\0' && goodemail[i][x] != '\0') {
          for(; mailfrom[j] != '.' && mailfrom[j] != '\0'; j++);
          if(mailfrom[j] != '\0')
            j++;

          x = 0;
          for(; mailfrom[j] != '\0'
              && goodemail[i][x] != '\0'
              && mailfrom[j] == goodemail[i][x]; x++, j++);

          if(mailfrom[j] == goodemail[i][x]
             && mailfrom[j] == '\0' && goodemail[i][x] == '\0') {
            /* Match .domain.com */
            if(DEBUG) {
              fprintf(stderr, " Checking %s against domain (%d) %s\n",
                      mailfrom, i, goodemail[i]);
              fprintf(stderr, "  Match GOOD Email .Domain: %s\n", mailfrom);
            }
            return (1);
          }
        }
      }
      break;
    case USER_AT_DOMAIN:
      if(my_strlen(mailfrom) == my_strlen(goodemail[i])) {
        if(!strncmp(mailfrom, goodemail[i], my_strlen(mailfrom))) {
          /* Match me@domain.com */
          if(DEBUG) {
            fprintf(stderr, " Checking %s against address (%d) %s\n",
                    mailfrom, i, goodemail[i]);
            fprintf(stderr, "  Match GOOD Email Address: %s\n", mailfrom);
          }
          return (1);
        }
      }
      break;
    default:
      break;
    }
  }

  /* Not good email */
  return (0);
}
