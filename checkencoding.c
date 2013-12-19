/* checkencoding.c */
static char *id = 
     "$Id: checkencoding.c,v 1.8 2002/08/16 16:22:35 bitbytebit Exp $";
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
#include <stdlib.h>
#include <ctype.h>
#include "my_string.h"
#include "max.h"

extern int DEBUG;
extern char *log_info;

int check_encoding(char *line, char *badencoding[])
{
  int i, j;
  char *p = NULL;
  char *buffer;

  buffer = malloc(my_strlen(line) + 1);

  /* go to '=' char or exit */
  if((p = strchr(line, ':')) != NULL) {
    p++;
    /* skip odd '3D' html thing */
    if(*p == '3') {
      p++;
      if(*p == 'D')
        p++;
    }
    if(*p == '"')
      p++;

    /* skip spaces and delimeters */
    while(*p == ' ' || *p == '(' || *p == '<' || *p == '@' || *p == ',' ||
          *p == ';' || *p == ':' || *p == '[' || *p == '?' ||
          *p == '.' || *p == '=')
      p++;

    /* Copy charset to buffer */
    for(j = 0; *p != '\0' && *p != '\n'; p++, j++) {
      /* stop at special delimiting characters */
      if(*p == ';' || *p == ' ' || *p == '"' || *p == '>' || *p == '=' ||
         *p == ')' || *p == '@' || *p == ',' || *p == ':' || *p == ']' ||
         *p == '.' || *p == '?')
        break;

      buffer[j] = *p;
    }
    buffer[j] = '\0';
  }
  for(j = 0; buffer[j] != '\0'; j++)
    buffer[j] = tolower(buffer[j]);

  /* Check charsets */
  for(i = 0; badencoding[i] != NULL; i++) {
    if(strstr(buffer, badencoding[i]) != NULL) {
      strsize = my_strlen(buffer) + my_strlen(badencoding[i]) + 3;
      log_info = malloc(strsize + 1);
      if(log_info == NULL)
        return (0);

      snprintf(log_info, strsize + 1, "(%s) %s", buffer, badencoding[i]);
      log_info[strsize] = (char)'\0';

      if(DEBUG)
        fprintf(stderr, " Match Bad Encoding %s\n", log_info);

      return 1;
    }
  }

  return 0;
}
