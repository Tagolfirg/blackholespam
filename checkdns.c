/* checkdns.c */
static char *id = 
     "$Id: checkdns.c,v 1.23 2002/08/16 16:22:35 bitbytebit Exp $";
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
#include "my_string.h"
#include "max.h"

#ifndef PACKETSZ
#define PACKETSZ 512
#endif

extern int DEBUG;
extern char *log_info;

int check_dns(char *mailfrom)
{
  char *domainrecord;
  u_char fixedans[PACKETSZ];
  u_char *answer;
  int length;
  int j, x;

  /* Internal mail server addresses */
  if(strcmp(mailfrom, "#@[]") == 0)
    return 1;
  else if(strcmp(mailfrom, "") == 0 && my_strlen(mailfrom) == 0)
    return 1;
  else if(strncasecmp(mailfrom, "mailer-daemon", 13) == 0)
    return 1;

  /* Make sure it contains an @ at least */
  if(strstr(mailfrom, "@")) {
    for(j = 0; mailfrom[j] != '@'; j++);
    j++;
  } else {
    /* No @ Symbol */
    strsize = my_strlen(mailfrom) + 12;
    log_info = malloc(strsize + 1);
    if(log_info == NULL)
      return 1;

    snprintf(log_info, strsize + 1, "(missing @) %s", mailfrom);
    log_info[strsize] = (char)'\0';

    if(DEBUG)
      fprintf(stderr, " Match Bad Sender DNS %s\n", log_info);

    return (0);
  }

  /* domain buffer */
  domainrecord = malloc(my_strlen(mailfrom) + 1);
  if(domainrecord == NULL)
    return 1;

  /* Put it into our domainrecord */
  for(x = 0; mailfrom[j] != '\0' && mailfrom[j] != ' '; x++, j++)
    domainrecord[x] = mailfrom[j];
  domainrecord[x] = '\0';

  /* DNS query. */
  res_init();
  answer = fixedans;
  length = res_query(domainrecord, C_IN, T_A, answer, PACKETSZ);
  if(length == -1)
    length = res_query(domainrecord, C_IN, T_MX, answer, PACKETSZ);

  /* Not a valid hostname */
  if(length == -1) {
    /* Bad Hostname */
    strsize = my_strlen(mailfrom) + 17;
    log_info = malloc(strsize + 1);
    if(log_info == NULL)
      return 1;

    snprintf(log_info, strsize + 1, "(invalid domain) %s", mailfrom);
    log_info[strsize] = (char)'\0';

    if(DEBUG)
      fprintf(stderr, " Match Bad Sender DNS %s\n", log_info);

    free(domainrecord);
    return 0;
  }

  if(length > PACKETSZ) {
    answer = malloc(length);
    length = res_query(domainrecord, C_IN, T_A, answer, length);
    if(length == -1)
      length = res_query(domainrecord, C_IN, T_MX, answer, PACKETSZ);
    if(length == -1) {
      /* Bad Hostname */
      strsize = my_strlen(mailfrom) + 17;
      log_info = malloc(strsize + 1);
      if(log_info == NULL)
        return 1;

      snprintf(log_info, strsize + 1, "(invalid domain) %s", mailfrom);
      log_info[strsize] = (char)'\0';

      if(DEBUG)
        fprintf(stderr, " Match Bad Sender DNS %s\n", log_info);

      free(domainrecord);
      free(answer);
      return 0;
    }
    free(answer);
  }

  /* Valid Domain */
  free(domainrecord);
  return 1;
}

