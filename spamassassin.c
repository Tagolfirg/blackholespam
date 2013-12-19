/* checkbody.c */
static char *id = 
     "$Id: spamassassin.c,v 1.3 2003/01/29 20:04:19 bitbytebit Exp $";
/*
   Copyright (C) 2002
        Craig Smith, Maximize IT.

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

#ifndef USE_MCONFIG
#include "config.h"
#endif
     
#if LIBSPAMC
#include "libspamc.h"
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sysexits.h>

#define SPAMD_HOST "127.0.0.1"
#define SPAMD_PORT 783

int call_spamc(FILE *tmp_msg, char *user, int maxsize) {
   struct message msg;
   FILE *tmp_sa_msg;
   int tmp_msg_fd;
   int err,flags,is_spam;
   struct sockaddr addr;

   tmp_msg_fd=fileno(tmp_msg);
   flags = SPAMC_RAW_MODE | SPAMC_SAFE_FALLBACK;
   
#if WITH_DEBUG == 1
       fprintf(stderr, "SpamAssassin Check\n");
#endif

   msg.max_len=maxsize;
   msg.type=MESSAGE_NONE;
   msg.raw=(char *)malloc(msg.max_len);
   
   err=lookup_host(SPAMD_HOST, SPAMD_PORT, &addr);
   if(err!=EX_OK) {
	   fprintf(stderr, "BARF on lookup_host (%d)\n",err);
	   return;
   }
   rewind(tmp_msg);
   err=message_read(tmp_msg_fd,SPAMC_RAW_MODE, &msg);
   if(err != EX_OK) {
	fprintf(stderr, "BARF on message_read (%d)\n",err);
	return;
   }
   err=message_filter(&addr, user, flags|SPAMC_CHECK_ONLY, &msg);
   if(err != EX_OK) {
	fprintf(stderr, "BARF on message_filter (%d)\n",err);
	return;
   }
   is_spam=msg.is_spam;
   /* 
    * We currently run the message through the filter twice.  Becuase
    * libspamc doesn't fill in all the msg structures w/o CHECK_ONLY
    * Until this is fixed or a better workaround comes up this is how
    * it is handled (one 'check only' and one real check)
    */
   rewind(tmp_msg);
   err=message_filter(&addr, user, flags, &msg);
   if(err != EX_OK) {
	fprintf(stderr, "BARF on message_filter (%d)\n",err);
	return;
   }
   rewind(tmp_msg);
   if(err=message_write(tmp_msg_fd, &msg)<0) {
	fprintf(stderr, "BARF on message_write (%d)\n",err);
	return;
   }
   /* Restore from the original is_spam check */
   msg.is_spam = is_spam;
   if(msg.is_spam == EX_TOOBIG) msg.is_spam=0; /* Ignore Too Big errs */

   return msg.is_spam;
}

#endif
