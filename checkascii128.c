/* checkascii128.c */
static char *id = 
     "$Id: checkascii128.c,v 1.12 2002/08/16 16:22:35 bitbytebit Exp $";
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

extern int DEBUG;
extern int ascii_score;
extern int max_ascii_score;
extern char *log_info;

int ascii_128(char *line)
{
  unsigned char *msg = line;

  for(; (*msg) && (ascii_score < max_ascii_score); msg++)
    if(isascii(*msg) == 0)
      ascii_score++;

  /* Matched our threshhold */
  if(ascii_score >= max_ascii_score) {
    strsize = typlen(int) + 13;
    log_info = malloc(strsize + 1);
    if(log_info == NULL)
      return 1;

    snprintf(log_info, strsize + 1,
             "(%d characters)", ascii_score);

    if(DEBUG)
      fprintf(stderr, " Match Ascii 128 %s\n", log_info);

    return 1;
  }
  return 0;
}
