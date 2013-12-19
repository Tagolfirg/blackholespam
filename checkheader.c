/* checkheader.c */
static char *id = 
     "$Id: checkheader.c,v 1.30 2002/09/23 18:03:51 bitbytebit Exp $";
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
#include "max.h"
#include "my_string.h"

int check_line(char *, char *);

extern int DEBUG;
extern char *log_info;

int checkheader(char *line, char *headers[])
{
  int i, j, x, f = 0;
  char *buffer, *buffer2;
  int nomatch = 0, positive = 0, position = 0, position2 = 0;

  if(line == NULL)
    return 0;

  /* See if header matches */
  for(i = 0; headers[i] != NULL; i++) {
  jumpback:
    positive = nomatch = position = position2 = 0;
    for(f = 0; line[f] != '\0' && headers[i][f] != '\0'; f++) {
      /* Found match, at the colons */
      if(line[f] == ':' && headers[i][f] == ':') {
        positive = 1;
        if(line[f+1] == ' ') {
          position = f += 2;
          position2 = position;
        } else {
          position = f += 2;
          position2 = position - 1;
        }
        break;
      }
      /* Compare with case insensitivity */
      if(tolower(line[position2]) != tolower(headers[i][position])) {
        break;
      }
    }
    /* Match, break out */
    if(positive == 1)
      break;
  }
  /* No Match */
  if(positive == 0) {
    i++;
    if(headers[i] != NULL)
      goto jumpback;
    else
      return 0;
  }

  buffer = (char *) malloc(my_strlen(line) + 1);
  if(buffer == NULL)
    return (0);

  buffer2 = (char *) malloc(my_strlen(headers[i]) + 1);
  if(buffer2 == NULL)
    return (0);

  if(headers[i][position] == '(' && headers[i][position + 1] == 'i' &&
     headers[i][position + 2] == ')') {
    /* Get value of header into buffer, convert to  lower case */
    for(f = position2, j = 0; line[f] != '\0' && line[f] != '\n'; f++, j++)
      buffer[j] = tolower(line[f]);
    buffer[j] = '\0';

    /* Get value of our option to compare to header value */
    for(f = position + 3, j = 0; headers[i][f] != '\0' && headers[i][f] != '\n';
        f++, j++)
      buffer2[j] = tolower(headers[i][f]);
    buffer2[j] = '\0';
  } else {
    /* Get value of header into buffer */
    for(f = position2, j = 0; line[f] != '\0' && line[f] != '\n'; f++, j++)
      buffer[j] = line[f];
    buffer[j] = '\0';

    /* Get value of our option to compare to header value */
    for(f = position, j = 0; headers[i][f] != '\0' && headers[i][f] != '\n';
        f++, j++)
      buffer2[j] = headers[i][f];
    buffer2[j] = '\0';
  }

  /* ^string$ */
  if(buffer2[0] == '^' && buffer2[my_strlen(buffer2) - 1] == '$') {
#if HAVE_LIBPCRE == 1
    if(check_line(buffer2, buffer) != 1) {
      i++;
      if(headers[i] != NULL)
        goto jumpback;
      else {
        free(buffer);
        free(buffer2);
        return 0;
      }
    } else {
#endif
      /* Check size and exit if not matching */
      if(my_strlen(buffer) != (my_strlen(buffer2) - 2)) {
        i++;
        if(headers[i] != NULL)
          goto jumpback;
        else {
          free(buffer);
          free(buffer2);
          return 0;
        }
      }

      /* Check character at a time */
      for(j = 0, x = 1; buffer2[x + 1] != '\0'; j++, x++) {
        if(buffer2[x] != buffer[j]) {
          i++;
          if(headers[i] != NULL)
            goto jumpback;
          else {
            free(buffer);
            free(buffer2);
            return 0;
          }
        }
      }
#if HAVE_LIBPCRE == 1
    }
#endif

    strsize = my_strlen(headers[i]) + 11;
    log_info = malloc(strsize + 1);
    if(log_info == NULL)
      return (1);

    snprintf(log_info, (strsize + 1), "(^string$) %s", headers[i]);
    log_info[strsize] = (char)'\0';

    if(DEBUG)
      fprintf(stderr, " Match Bad Header %s:\n  %s\n", log_info, buffer);

    free(buffer);
    free(buffer2);
    return 1;
    /* string$ */
  } else if(buffer2[my_strlen(buffer2) - 1] == '$') {
#if HAVE_LIBPCRE == 1
    if(check_line(buffer2, buffer) != 1) {
        nomatch = 1;
    } else {
#endif
      /* Check size and exit if not matching */
      for(j = 0, x = 0; buffer2[x + 1] != '\0'; j++) {
        if(buffer[j] == '\0') {
          nomatch = 1;
          break;
        }

        if(buffer2[x] == buffer[j]) {
          for(; buffer2[x + 1] != '\0'; x++, j++) {
            if(buffer[j] == '\0') {
              nomatch = 1;
              break;
            }
            if(buffer2[x] != buffer[j]) {
              nomatch = 1;
              break;
            }
          }
        }
      }
#if HAVE_LIBPCRE == 1
    }
#endif

    if(!nomatch) {
      strsize = my_strlen(headers[i]) + 10;
      log_info = malloc(strsize + 1);
      if(log_info == NULL)
        return 1;

      snprintf(log_info, strsize + 1, "(string$) %s", headers[i]);

      if(DEBUG)
        fprintf(stderr, " Match Bad Header %s:\n  %s\n", log_info, buffer);

      free(buffer);
      free(buffer2);
      return 1;
    } else {
      nomatch = 0;
      i++;
      if(headers[i] != NULL)
        goto jumpback;
      else {
        free(buffer);
        free(buffer2);
        return 0;
      }
    }
    /* ^string */
  } else if(buffer2[0] == '^') {
#if HAVE_LIBPCRE == 1
    if(check_line(buffer2, buffer) != 1) {
        nomatch = 1;
    } else {
#endif
      for(j = 0, x = 1; buffer2[x] != '\0'; j++, x++) {
        if(buffer[j] == '\0') {
          nomatch = 1;
          break;
        }
        if(buffer2[x] != buffer[j]) {
          nomatch = 1;
          break;
        }
      }
#if HAVE_LIBPCRE == 1
    }
#endif

    if(!nomatch) {
      strsize = my_strlen(headers[i]) + 10;
      log_info = malloc(strsize + 1);
      if(log_info == NULL)
        return 1;

      snprintf(log_info, 
           strsize + 1, "(^string) %s", headers[i]);

      if(DEBUG)
        fprintf(stderr, " Match Bad Header %s:\n  %s\n", log_info, buffer);

      free(buffer);
      free(buffer2);
      return 1;
    } else {
      nomatch = 0;
      i++;
      if(headers[i] != NULL)
        goto jumpback;
      else {
        free(buffer);
        free(buffer2);
        return 0;
      }
    }
    /* string */
  } else {
    if(buffer != NULL && buffer2 != NULL) {
      nomatch = 1;
#if HAVE_LIBPCRE == 1
      if(check_line(buffer2, buffer) == 1) {
          nomatch = 0;
      } else {
#endif
        if(strstr(buffer, buffer2) != NULL)
          nomatch = 0;
#if HAVE_LIBPCRE == 1
      }
#endif

      if(nomatch == 0) {
        strsize = my_strlen(headers[i]) + 9;
        log_info = malloc(strsize + 1);
        if(log_info == NULL)
          return 1;

        snprintf(log_info, strsize+1, "(string) %s", headers[i]);
        log_info[strsize] = (char)'\0';

        if(DEBUG)
          fprintf(stderr, " Match Bad Header %s:\n  %s\n", log_info, buffer);

        return 1;
      } else {
        i++;
        if(headers[i] != NULL)
          goto jumpback;
        else {
          free(buffer);
          free(buffer2);
          return 0;
        }
      }
    }
  }

  i++;
  if(headers[i] != NULL)
    goto jumpback;
  else {
    free(buffer);
    free(buffer2);
    return 0;
  }
}
