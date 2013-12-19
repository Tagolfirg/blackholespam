/* execute.c */
static char *id = 
     "$Id: execute.c,v 1.9 2002/09/11 20:31:32 bitbytebit Exp $";
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
#include "execute.h"

int get_file_size(char *);

extern int DEBUG;
extern char *tmp_file;
extern char *log_info;
extern char *exec_report_prog;
extern char *exec_report_args;

int execute(char *spamhost, char *spammsg, int flag)
{
  int pid, status;

  /* Skip over zero byte file */
  if(get_file_size(tmp_file) == 0)
    return 0;

  /* Fork for Program */
  pid = fork();
  if(pid == -1) {
    fprintf(stderr,
            "%s: Error Spawning Pid! %s:%d\n", __FILE__, __FILE__, __LINE__);
    return 0;
  }
  if(pid == 0) {
    if(flag == REPORT && exec_report_args == NULL) {
      char *execute_args[] = {
        PROGEXEC,
#ifdef PROGEXEC_ARGS
        PROGEXEC_ARGS
#endif
        spamhost,
        spammsg,
        '\0'
      };

      /* Run the program */
      if(exec_report_prog == NULL)
        execv(PROGEXEC, execute_args);
      else
        execv(exec_report_prog, execute_args);
    } else if(flag == REPORT) {
      char *execute_args[] = {exec_report_prog, '\0'};
      arraycat(execute_args, exec_report_args);
      arraycat(execute_args, spamhost);
      arraycat(execute_args, spammsg);

      /* Run the program */
      if(exec_report_prog == NULL)
        execv(PROGEXEC, execute_args);
      else
        execv(exec_report_prog, execute_args);
    } else {
      char *execute_args[] = {
        EXEC_CHECK_PROG,
#ifdef EXEC_CHECK_ARGS
        EXEC_CHECK_ARGS
#endif
        spamhost,
        spammsg,
        '\0'
      };

      /* Run the program */
      execv(EXEC_CHECK_PROG, execute_args);
    } 

    /* Error if still here */
    fprintf(stderr, "Error Executing %s\n", exec_report_prog);
    exit(127);
  }
  do {
    if(waitpid(pid, &status, 0) == -1) {
      if(errno != EINTR) {
        fprintf(stderr, "%s: Error Executing %s! %s:%d\n",
                PROGEXEC, __FILE__, __FILE__, __LINE__);
        return -1;
      }
    } else {
      status >>= 8;
      status &= 0xFF;

      if(flag == REPORT && exec_report_prog == NULL) {
        if(status == 0) {
#if WITH_DEBUG == 1
          if(DEBUG) {
            fprintf(stderr, "Ran program %s (%d)\n", PROGEXEC, status);
            if(exec_report_args == NULL) 
              fprintf(stderr, "  args: %s %s\n", spamhost, spammsg );
            else
              fprintf(stderr, "  args: %s %s %s\n",
                   exec_report_args, spamhost, spammsg );
          }
#endif
          return 0;
        } else if(DEBUG)
          fprintf(stderr, "Error with program %s (%d)\n", PROGEXEC, status);
      } else if(flag == REPORT) {
        if(status == 0) {
#if WITH_DEBUG == 1
          if(DEBUG) {
            fprintf(stderr, "Ran program %s (%d)\n", exec_report_prog, status);
            if(exec_report_args == NULL) 
              fprintf(stderr, "  args: %s %s\n", spamhost, spammsg );
            else
              fprintf(stderr, "  args: %s %s %s\n",
                   exec_report_args, spamhost, spammsg );
          }
#endif
          return 0;
        } else if(DEBUG)
          fprintf(stderr, 
               "Error with program %s (%d)\n", exec_report_prog, status);
          if(exec_report_args == NULL) 
            fprintf(stderr, "  args: %s %s\n", spamhost, spammsg );
          else
            fprintf(stderr, "  args: %s %s %s\n",
                 exec_report_args, spamhost, spammsg );
      } else {
#if WITH_DEBUG == 1
        if(DEBUG) {
          fprintf(stderr, 
               "Ran Check program %s (%d)\n", EXEC_CHECK_PROG, status);
        }
#endif
        if(status == EXEC_CHECK_RET) {
          strsize = my_strlen(EXEC_CHECK_PROG) + typlen(int) + 10;
          log_info = malloc(strsize + 1);
          if(log_info == NULL)
            return 1;
      
          snprintf(log_info, 
               strsize + 1, "(status %d) %s", status, EXEC_CHECK_PROG);
          log_info[strsize] = (char)'\0';
      
#if WITH_DEBUG == 1
          if(DEBUG)
            fprintf(stderr, " Match Exec Program %s\n", log_info);
#endif

          return 1;
        }
      }

      break;
    }
  } while(1);

  /* Return OK */
  return 0;
}

