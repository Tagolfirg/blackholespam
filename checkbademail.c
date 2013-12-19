/* checkbademail.c */
static char *id = 
     "$Id: checkbademail.c,v 1.21 2002/08/24 18:10:38 bitbytebit Exp $";
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

#define USER_AT_DOMAIN 	1
#define BARE_DOMAIN     2
#define AT_DOMAIN  	3
#define DOT_DOMAIN 	4
#define BARE_USER       5

extern int DEBUG;
extern char *log_info;

int checkbademail(char *mailfrom, char *bademail[])
{
  int i, j = 0, x = 0;
  int type = 0;

  for(i = 0; bademail[i] != NULL; i++) {
    /* Figure out filter type */
    if(bademail[i][0] == '@') {
      type = AT_DOMAIN;
    } else if(bademail[i][0] == '.') {
      type = DOT_DOMAIN;
    } else if(!strstr(bademail[i], "@") && !strstr(bademail[i], ".")) {
      type = BARE_USER;
    } else if(!strstr(bademail[i], "@")) {
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
            && bademail[i][x] != '\0'
            && mailfrom[j] == bademail[i][x]; x++, j++);

        if(mailfrom[j] == bademail[i][x]) {
          /* Match @domain.com */
          strsize = (my_strlen(bademail[i]) + 10);
          log_info = malloc(strsize + 1);
          if(log_info == NULL)
            return (1);

          snprintf(log_info, strsize + 1, "(@domain) %s", bademail[i]);

          if(DEBUG)
            fprintf(stderr, " Match Bad Email %s\n", log_info);

          return (1);
        }
      }
      break;
    case DOT_DOMAIN:
      if(strstr(mailfrom, "@")) {
        j = 0;
        while(mailfrom[j] != '\0' && bademail[i][x] != '\0') {
          for(; mailfrom[j] != '.' && mailfrom[j] != '\0'; j++);
          if(mailfrom[j] != '\0')
            j++;

          x = 1;
          for(; mailfrom[j] != '\0'
              && bademail[i][x] != '\0'
              && mailfrom[j] == bademail[i][x]; x++, j++);

          if(mailfrom[j] == bademail[i][x]
             && mailfrom[j] == '\0' && bademail[i][x] == '\0') {
            /* Match .domain.com */
            strsize = (my_strlen(bademail[i]) + 10);
            log_info = malloc(strsize + 1);
            if(log_info == NULL)
              return (1);

            snprintf(log_info, strsize + 1, "(.domain) %s", bademail[i]);

            if(DEBUG)
              fprintf(stderr, " Match Bad Email %s\n", log_info);

            return (1);
          }
        }
      }
      break;
    case BARE_USER:
      if(strncmp(mailfrom, bademail[i], my_strlen(mailfrom)) == 0) {
        /* Match Username */
        strsize = (my_strlen(bademail[i]) + 11);
        log_info = malloc(strsize + 1);
        if(log_info == NULL)
          return (1);

        snprintf(log_info, strsize + 1, "(username) %s", bademail[i]);

        if(DEBUG)
          fprintf(stderr, " Match Bad Email %s\n", log_info);

        return (1);
      }
      break;
    case BARE_DOMAIN:
      if(strstr(mailfrom, "@")) {
        for(j = 0; mailfrom[j] != '@'; j++);
        j++;

        for(x = 0; mailfrom[j] != '\0'
            && bademail[i][x] != '\0'
            && mailfrom[j] == bademail[i][x]; x++, j++);

        if(mailfrom[j] == bademail[i][x]) {
          /* Match domain.com */
          strsize = (my_strlen(bademail[i]) + 9);
          log_info = malloc(strsize + 1);
          if(log_info == NULL)
            return (1);

          snprintf(log_info, strsize + 1, "(domain) %s", bademail[i]);

          if(DEBUG)
            fprintf(stderr, " Match Bad Email %s\n", log_info);

          return (1);
        }
      }
      if(strstr(mailfrom, "@")) {
        j = 0;
        while(mailfrom[j] != '\0' && bademail[i][x] != '\0') {
          for(; mailfrom[j] != '.' && mailfrom[j] != '\0'; j++);
          if(mailfrom[j] != '\0')
            j++;

          x = 0;
          for(; mailfrom[j] != '\0'
              && bademail[i][x] != '\0'
              && mailfrom[j] == bademail[i][x]; x++, j++);

          if(mailfrom[j] == bademail[i][x]
             && mailfrom[j] == '\0' && bademail[i][x] == '\0') {
            /* Match .domain.com */
            strsize = (my_strlen(bademail[i]) + 10);
            log_info = malloc(strsize + 1);
            if(log_info == NULL)
              return (1);

            snprintf(log_info, strsize + 1, "(.domain) %s", bademail[i]);

            if(DEBUG)
              fprintf(stderr, " Match Bad Email %s\n", log_info);

            return (1);
          }
        }
      }
      break;
    case USER_AT_DOMAIN:
      if(my_strlen(mailfrom) == my_strlen(bademail[i])) {
        if(!strncmp(mailfrom, bademail[i], my_strlen(mailfrom))) {
          /* Match me@domain.com */
          strsize = (my_strlen(bademail[i]) + 14);
          log_info = malloc(strsize + 1);
          if(log_info == NULL)
            return (1);

          snprintf(log_info, strsize + 1, "(user@domain) %s", bademail[i]);

          if(DEBUG)
            fprintf(stderr, " Match Bad Email %s\n", log_info);

          return (1);
        }
      }
      break;
    default:
      break;
    }
  }

  /* Not bad email */
  return (0);
}
