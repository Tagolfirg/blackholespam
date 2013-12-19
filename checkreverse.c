/* checkreverse.c */
static char *id = 
     "$Id: checkreverse.c,v 1.15 2002/08/16 16:22:35 bitbytebit Exp $";
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
#include <arpa/inet.h>
#include <sys/socket.h>
#include "my_string.h"
#include "max.h"

#ifndef PACKETSZ
#define PACKETSZ 512
#endif

extern int DEBUG;
extern char *log_info;
extern int checkhelo;

int check_reverse(char *iprelay, char *hostrelay)
{
  u_char fixedans[PACKETSZ];
  u_char *answer;
  int length;
  struct hostent *host_ent;
  struct in_addr address;
  char *iprelay_rev;
  int a, b, c, d;

  /* Reverse the relay ip into .in-addr.arpa. */
  if(sscanf(iprelay, "%d.%d.%d.%d", &a, &b, &c, &d) != 4 ||
     a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 ||
     d < 0 || d > 255) {
    return 1;
  }
  strsize = MAX_RELAY_SIZE + strlen(".in-addr.arpa");
  iprelay_rev = malloc(strsize + 1);
  if(iprelay_rev == NULL)
    return 1;
  snprintf(iprelay_rev,  
       strsize + 1, "%d.%d.%d.%d.%s", d, c, b, a, "in-addr.arpa");
  iprelay_rev[strsize] = (char)'\0';

  /* DNS query. */
  res_init();
  answer = fixedans;

  /* Straight Relay IP Reverse DNS Check */
  length = res_query(iprelay_rev, C_IN, T_PTR, answer, PACKETSZ);
  free(iprelay_rev);
  /* Not a valid hostname from relay ip */
  if(length == -1) {
    /* Bad Hostname */
    strsize = my_strlen(iprelay) + 13;
    log_info = malloc(strsize + 1);
    if(log_info == NULL)
      return 1;

    snprintf(log_info, strsize + 1, "(invalid ip) %s", iprelay);
    log_info[strsize] = (char)'\0';

    if(DEBUG)
      fprintf(stderr, " Match Reverse DNS %s\n", log_info);

    return 0;
  }

  /* OK if not setup for strict checking */
  if(checkhelo < 1)
    return 1;

  /* Check Helo */
  length = res_query(hostrelay, C_IN, T_A, answer, PACKETSZ);
  if(length == -1)
    length = res_query(hostrelay, C_IN, T_MX, answer, PACKETSZ);

  /* Not a valid hostname */
  if(length == -1) {
    /* Bad Hostname */
    strsize = my_strlen(hostrelay) + 15;
    log_info = malloc(strsize + 1);
    if(log_info == NULL)
      return 1;

    snprintf(log_info, strsize + 1, "(invalid helo) %s", hostrelay);
    log_info[strsize] = (char)'\0';

    if(DEBUG)
      fprintf(stderr, " Match Helo Host %s\n", log_info);

    return 0;
  }

  if(length > PACKETSZ) {
    answer = malloc(length);
    length = res_query(hostrelay, C_IN, T_A, answer, length);
    if(length == -1)
      length = res_query(hostrelay, C_IN, T_MX, answer, PACKETSZ);
    if(length == -1) {
      /* Bad Hostname */
      strsize = my_strlen(hostrelay) + 15;
      log_info = malloc(strsize + 1);
      if(log_info == NULL)
        return 1;

      snprintf(log_info, strsize + 1, "(invalid helo) %s", hostrelay);
      log_info[strsize] = (char)'\0';

      if(DEBUG)
        fprintf(stderr, " Match Helo Host %s\n", log_info);

      free(answer);
      return 0;
    }
    free(answer);
  }

  /* Get Hostname from IP */
  host_ent = gethostbyname(hostrelay);
  if(host_ent == NULL)
    return 1;
  memcpy(&address, host_ent->h_addr, 4);

  /* Compare relay ip with ip of hostname it resolves to in reverse */
  if(strncmp(iprelay, inet_ntoa(address), my_strlen(iprelay)) != 0) {
    /* Bad Hostname */
    strsize = my_strlen(iprelay) + 18;
    log_info = malloc(strsize + 1);
    if(log_info == NULL)
      return 1;

    snprintf(log_info, strsize + 1, "(invalid helo/ip) %s", iprelay);
    log_info[strsize] = (char)'\0';

    if(DEBUG)
      fprintf(stderr, " Match Reverse DNS Helo %s\n", log_info);

    return 0;
  }

  /* Valid Domain */
  return 1;
}
