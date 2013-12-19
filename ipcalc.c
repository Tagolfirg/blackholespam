/* ipcalc.c */
static char *id = 
     "$Id: ipcalc.c,v 1.14 2002/08/08 20:08:07 bitbytebit Exp $";
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
#include <ctype.h>
#include <string.h>

int ipcalc(char *ip1, char *ip2)
{
  unsigned int a[4];
  unsigned int b[4];
  int cidr_diff = 0;
  int i, x, maxaddr, cidr;

  if(strstr(ip1, ".") == 0 || strstr(ip2, ".") == 0)
    return 0;

  /* Split up into bytes */
  if(sscanf(ip1, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]) != 4 ||
     a[0] < 0 || a[0] > 255 || a[1] < 0 || a[1] > 255 ||
     a[2] < 0 || a[2] > 255 || a[3] < 0 || a[3] > 255) {
    return 0;
  }

  if((i =
      sscanf(ip2, "%d.%d.%d.%d/%d", &b[0], &b[1], &b[2], &b[3], &cidr)) != 5) {
    if(i == 4) {
      if(b[0] < 0 || b[0] > 255 || b[1] < 0 || b[1] > 255 ||
         b[2] < 0 || b[2] > 255 || b[3] < 0 || b[3] > 255)
        return 0;
      cidr = 32;
    } else if(i == 3) {
      if(b[0] < 0 || b[0] > 255 || b[1] < 0 || b[1] > 255 ||
         b[2] < 0 || b[2] > 255)
        return 0;
      cidr = 24;
    } else if(i == 2) {
      if(b[0] < 0 || b[0] > 255 || b[1] < 0 || b[1] > 255)
        return 0;
      cidr = 16;
    } else if(i == 1) {
      if(b[0] < 0 || b[0] > 255)
        return 0;
      cidr = 8;
    } else
      return 0;
    /* Invalid address */
  } else if(b[0] < 0 || b[0] > 255 || b[1] < 0 || b[1] > 255 ||
            b[2] < 0 || b[2] > 255 || b[3] < 0 || b[3] > 255 || cidr > 32)
    return 0;

  /* Walk through matching up to classless portion */
  for(i = 0; i < (cidr / 8); i++) {
    /* No Match */
    if((a[i] ^ b[i]) != 0)
      return 0;
  }

  /* Host match */
  if((cidr % 8) == 0)
    return 1;

  /* Find leftover bits */
  if(cidr > 8)
    cidr_diff = 8 - (cidr % 8);
  else
    cidr_diff = (8 - cidr);

  /* Grow exponetially for each bit */
  for(maxaddr = 1, x = 1; x <= cidr_diff; maxaddr += maxaddr, x++);
  maxaddr--;

  /* No Match, less than netmask or not even, or max is odd */
  if(a[i] < b[i] || (maxaddr % 1) > 0)
    return 0;

  /* No Match, greater than max address */
  if((a[i] ^ b[i]) > maxaddr)
    return 0;

  /* Match */
  return 1;
}
