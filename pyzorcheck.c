/* pyzorcheck.c */
static char *id = 
     "$Id: pyzorcheck.c,v 1.4 2002/08/16 16:22:35 bitbytebit Exp $";
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
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "my_string.h"
#include "max.h"

int get_file_size(char *);

extern int DEBUG;
extern char *tmp_file;
extern char *log_info;

extern char *pyzor_bin;
extern char *python_bin;

int pyzor_check(void)
{
  int pid, status;

  /* Skip over zero byte file */
  if(get_file_size(tmp_file) == 0)
    return 0;

  /* Fork for Pyzor */
  pid = fork();
  if(pid == -1) {
    fprintf(stderr,
            "%s: Error Spawning Pid! %s:%d\n", __FILE__, __FILE__, __LINE__);
    return 0;
  }
  if(pid == 0) {
      char *pyzor_args[] = {
	  pyzor_bin,
	  "check",
	  '\0'
      };
      freopen(tmp_file, "r", stdin);
      /* Razor check the message */
      execv(pyzor_bin, pyzor_args);

      /* Error if still here */
      fprintf(stderr, "Error Pyzor Checking\n");
      exit(127);
  }
  do {
    if(waitpid(pid, &status, 0) == -1) {
      if(errno != EINTR) {
        fprintf(stderr, "%s: Error Executing Pyzor! %s:%d\n",
                __FILE__, __FILE__, __LINE__);
        return -1;
      }
    } else {
      status >>= 8;
      status &= 0xFF;

      if(status == 0) {
        strsize = typlen(int) + 9;
        log_info = malloc(strsize + 1);
        if(log_info == NULL)
          return 1;
        snprintf(log_info, strsize + 1, "(status %d)", status);

        if(DEBUG)
          fprintf(stderr, " Match Pyzor %s\n", log_info);

        return 1;
      } else if(DEBUG && status != 1)
        fprintf(stderr, "Error with Pyzor (%d)\n", status);

      break;
    }
  } while(1);

  /* Return OK */
  return 0;
}

