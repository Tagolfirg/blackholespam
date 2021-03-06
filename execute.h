/* execute.h */
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
#ifndef _EXECUTE_H
#define _EXECUTE_H 1

#ifndef USE_MCONFIG
#include "config.h"
#endif

int arraycat(char *[], char *);

#define REPORT 0

/* PROGRAM */
#ifndef PROGEXEC
#define PROGEXEC "/usr/local/bin/spamcomplain"
#endif

/* PROGRAM ARGS */
#ifndef PROGEXEC_ARGS
#define PROGEXEC_ARGS \
	"", \
	"",
#endif

/* RET */
#ifndef EXEC_CHECK_RET
#define EXEC_CHECK_RET 1
#endif

/* PROG */
#ifndef EXEC_CHECK_PROG
#define EXEC_CHECK_PROG "/opt/blackhole/bin/spamcheck"
#endif

/* ARGS */
#ifndef EXEC_CHECK_ARGS
#define EXEC_CHECK_ARGS \
	"", \
	"",
#endif

#endif /* _VIRUS_H */
