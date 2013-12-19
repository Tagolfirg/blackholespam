/* max.h */
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
#ifndef _MAX_H
#define _MAX_H 1

#ifndef USE_MCONFIG
#include "config.h"
#endif

/* for all string size operations */
int strsize;

#ifndef MAXOPTION
#define MAXOPTION 500
#endif

#ifndef MAX_CONFIG_LINE
#define MAX_CONFIG_LINE 255
#endif

#ifndef MAX_INPUT_LINE
#define MAX_INPUT_LINE 1003
#endif

#ifndef MAX_EMAIL_SIZE
#define MAX_EMAIL_SIZE 196
#endif

#ifndef MAX_MYSQL_FIELDS
#define MAX_MYSQL_FIELDS 255
#endif

#ifndef MAX_HOMEDIR_SIZE
#define MAX_HOMEDIR_SIZE 1024
#endif

#ifndef MAX_RELAY_SIZE
#define MAX_RELAY_SIZE 64
#endif

#ifndef MAX_CORE_SIZE
#define MAX_CORE_SIZE 2000000
#endif

#ifndef MAX_ACTIONS
#define MAX_ACTIONS 30
#endif

#ifdef CLAMSCAN_DAEMON
#define CLAMSCAN_DAEMON_SOCKET_LEN 103
#endif

#endif /* _MAX_H */
