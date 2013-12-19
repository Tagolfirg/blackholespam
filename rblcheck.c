/* rblcheck.c */
static char *id = 
     "$Id: rblcheck.c,v 1.18 2003/01/02 18:52:05 bitbytebit Exp $";
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
/* some DNS code borrowed from: 
 * rblcheck 1.4 - Command-line interface to Paul Vixie's RBL filter.
 * Copyright (C) 1997, Edward S. Marshall <emarshal@logic.net>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "my_string.h"
#include "max.h"

#ifndef PACKETSZ
#define PACKETSZ 512
#endif

extern char *dns_srv;

int rblcheck(int a, int b, int c, int d, char *rbldomain)
{
  char *domainrecord;
  u_char fixedans[PACKETSZ];
  u_char *answer;
  int length;

  struct in_addr addr;

  /* Build domain lookup */
  strsize = 16 + my_strlen(rbldomain);
  domainrecord = (char *) malloc(strsize + 1);
  if(domainrecord == NULL)
    return (0);
  snprintf(domainrecord,  strsize + 1, "%d.%d.%d.%d.%s", d, c, b, a, rbldomain);
  domainrecord[strsize] = (char)'\0';

  /* DNS query. */
  res_init();

  /* Specify the DNS server to use */
  if(dns_srv != NULL) {
    inet_aton(dns_srv, &addr);
    _res.nsaddr_list[0].sin_addr = addr;
    _res.nsaddr_list[0].sin_family = AF_INET;
    _res.nsaddr_list[0].sin_port = htons(NAMESERVER_PORT);
    _res.nscount = 1;
  }

  answer = fixedans;
  length = res_query(domainrecord, C_IN, T_A, answer, PACKETSZ);

  /* Not on RBL List */
  if(length == -1) {
    free(domainrecord);
    return 0;
  }

  if(length > PACKETSZ) {
    answer = malloc(length);
    length = res_query(domainrecord, C_IN, T_A, answer, length);
    if(length == -1)
      return 0;
    free(answer);
  }

  /* On the RBL List */
  free(domainrecord);
  return 1;
}
