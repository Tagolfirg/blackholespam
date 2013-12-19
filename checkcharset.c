/* checkcharset.c */
static char *id = 
     "$Id: checkcharset.c,v 1.24 2002/08/20 22:38:44 bitbytebit Exp $";
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

int check_charset(char *line, char *charsets[])
{
  int i, j;
  char *p = NULL;
  char *buffer;

  buffer = malloc(my_strlen(line) + 1);

  if((p = strstr(line, "charset")) != NULL ||
     (p = strstr(line, "Charset")) != NULL ||
     (p = strstr(line, "CHARSET")) != NULL) {
    /* skip by the '=' char or exit */
    for(;*p != '\0' && *p != '=';p++);
    if(*p == '=')
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
          *p == ';' || *p == ':' || *p == '/' || *p == '[' || *p == '?' ||
          *p == '.' || *p == '=')
      p++;

    /* Copy charset to buffer */
    for(j = 0; *p != '\0' && *p != '\n'; p++, j++) {
      /* stop at special delimiting characters */
      if(*p == ';' || *p == ' ' || *p == '"' || *p == '>' || *p == '=' ||
         *p == ')' || *p == '@' || *p == ',' || *p == ':' || *p == ']' ||
         *p == '.' || *p == '?' || *p == '/')
        break;

      buffer[j] = *p;
    }
    buffer[j] = '\0';
  }
  for(j = 0; buffer[j] != '\0'; j++)
    buffer[j] = tolower(buffer[j]);

  /* Check charsets */
  for(i = 0; charsets[i] != NULL; i++) {
    if(strstr(buffer, charsets[i]) != NULL) {
      return 1;
    }
  }

  /* Nothing in buffer */
  if(my_strlen(buffer) == 0)
    return 1;

  strsize = my_strlen(buffer) + 2;
  log_info = malloc(strsize + 1);
  if(log_info == NULL)
    return (1);

  snprintf(log_info, strsize + 1, "(%s)", buffer);
  log_info[strsize] = (char)'\0';

  if(DEBUG)
    fprintf(stderr, " Match Charset %s\n", log_info);

  return 0;
}

