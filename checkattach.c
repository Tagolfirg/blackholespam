/* checkattach.c */
static char *id = 
     "$Id: checkattach.c,v 1.3 2002/08/20 22:38:44 bitbytebit Exp $";
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

#ifndef USE_MCONFIG
#include "config.h"
#endif

#include "my_string.h"
#include "max.h"

extern int DEBUG;
extern char *log_info;

#if HAVE_LIBPCRE == 1
int check_line(char *, char *);
#endif

int check_attach(char *line, char *badattach[])
{
  int i, j;
  char *p = NULL;
  char *buffer;

  buffer = malloc(my_strlen(line) + 1);

  if((p = strstr(line, "name")) != NULL ||
     (p = strstr(line, "Name")) != NULL ||
     (p = strstr(line, "NAME")) != NULL) {
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
    while(*p == ' ' || *p == '=')
      p++;

    /* Copy charset to buffer */
    for(j = 0; *p != '\0' && *p != '\n'; p++, j++) {
      /* stop at special delimiting characters */
      if(*p == ';' || *p == '"' || *p == '=')
        break;

      buffer[j] = *p;
    }
    buffer[j] = '\0';
  }
  for(j = 0; buffer[j] != '\0'; j++)
    buffer[j] = tolower(buffer[j]);

  /* Nothing in buffer */
  if(my_strlen(buffer) == 0)
    return 0;

  /* Check badattach */
  for(i = 0; badattach[i] != NULL; i++) {
#if HAVE_LIBPCRE == 1
    if(check_line(badattach[i], buffer) == 1) {
#else
    if(strstr(buffer, badattach[i]) != NULL) {
#endif
      strsize = my_strlen(buffer) + my_strlen(badattach[i]) + 8;
      log_info = malloc(strsize + 1);
      if(log_info == NULL)
        return 1;

      snprintf(log_info, strsize + 1, "(file %s) %s", buffer, badattach[i]);
      log_info[strsize] = (char)'\0';

      if(DEBUG)
        fprintf(stderr, " Match Attachment %s\n", log_info);

      /* Bad Attachment */
      return 1;
    }
  }

  /* Message OK */
  return 0;
}

