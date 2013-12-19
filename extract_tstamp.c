/* extract_timestamp.c */
static char *id = 
     "$Id: extract_tstamp.c,v 1.7 2002/08/08 20:08:07 bitbytebit Exp $";
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

int extract_tstamp(char *buffer, char *host)
{
  int j;
  char *p = NULL;

  if((p = strchr(buffer, ';')) != NULL) {
    if(*p != '\0')
      p++;
    else
      return 0;
    if(*p == ' ')
      p++;
    else
      return 0;

    /* Copy timestamp to buffer */
    for(j = 0; *p != '\0' && *p != '\n'; p++, j++)
      host[j] = *p;
    host[j] = '\0';
  }

  return 0;
}

