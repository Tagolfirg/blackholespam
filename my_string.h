/* my_string.h */
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
#ifndef _MY_STRING_H
#define _MY_STRING_H 1

#ifndef u_char
#define u_char unsigned char
#endif

int my_strlen(char *);
size_t my_strlcpy(char *, const char *, size_t);
size_t my_strlcat(char *, const char *, size_t);

#define typlen(type)     ((sizeof(type)*8+2)/3+1)

#endif /* _MY_STRING_H */

