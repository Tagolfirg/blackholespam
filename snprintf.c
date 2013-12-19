/* snprintf.c */
static char *id = 
     "$Id: snprintf.c,v 1.8 2002/08/08 20:08:07 bitbytebit Exp $";
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
#include <stdarg.h>
#include <sys/types.h>
#include <stdio.h>

int my_snprintf(char *str,size_t size,const char *format,...)
{
  int n;
  va_list arg_ptr;

  /* Null Terminate String at End */
  if(str[size-1] != '\0')
    str[size-1] = (char)'\0';

  va_start(arg_ptr, format);
  n=vsnprintf(str,size,format,arg_ptr);
  va_end (arg_ptr);

  return n;
}
