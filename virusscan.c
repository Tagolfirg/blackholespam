/* virusscan.c */
static char *id =
     "$Id: virusscan.c,v 1.60 2003/01/02 14:16:24 bitbytebit Exp $";
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
#ifndef USE_MCONFIG
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "virus.h"
#include "max.h"
#include "my_string.h"
#include "misc.h"

#ifdef CLAMSCAN_DAEMON
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif /* CLAMSCAN_DAEMON */

int get_file_size(char *);
int mime_parse(char *);
int rmdir_r(char *);

extern int virus_checker;
#if VIRUS_SCANNER == SOPHOSSDK
int sophos(char *);
#elif VIRUS_SCANNER == TRENDMICRO
int tmicro(char *);
#endif
extern int DEBUG;
extern int disinfect;
extern char *tmp_file;
extern char *spool_dir;
extern char *uvscan;
extern char *clamscan;
extern char *dat_dir;
extern char *virus_type;

extern int found_virus;

extern char *mime_dir;

int virus_scan(void)
{
  int pid, status;
  FILE *f;
  char *tmp_log;
  char *line;
  pid_t mypid;
  time_t mytime;
  int virus_status = 0;

#ifdef CLAMSCAN_DAEMON
  char clam_request[FILENAME_MAX + 8];
  struct sockaddr_un address;
  char *start, *end, *copy;
  int sockfd, loop;
  size_t size;
#endif /* CLAMSCAN_DAEMON */

#if WITH_DEBUG == 1
  if(DEBUG)
    fprintf(stderr, "Virus Scanning: %s\n", tmp_file);
#endif

  /* Skip over zero byte file */
  if(get_file_size(tmp_file) == 0) {
#if WITH_DEBUG == 1
    if(DEBUG)
      fprintf(stderr, "Skipping Zero sized file: %s\n", tmp_file);
#endif
    return 0;
  }

  if(virus_checker == SOPHOSSDK || virus_checker == TRENDMICRO) {
#if VIRUS_SCANNER == SOPHOSSDK
    sophos(tmp_file);
#elif VIRUS_SCANNER == TRENDMICRO
    tmicro(tmp_file);
#endif
    if(found_virus == 1) {
      if(disinfect > 0) {
        status = 19;
        virus_status = 2;
      } else {
        status = 13;
        virus_status = 1;
      }
      if(DEBUG)
        fprintf(stderr, "  Match Virus Type: %s\n", virus_type);
    } else
      status = 0;
  } else {     /* ClamScan or McAfee */
    /* Time and Pid for Filename */
    time(&mytime);
    mypid = getpid();

    /* line buffer for parsing Virus Output */
    line = malloc(MAX_INPUT_LINE + 1);
    if(bh_assert(line == NULL))
      return 0;

    /* virus_type size */
    virus_type = malloc(MAX_INPUT_LINE + 1);
    if(bh_assert(virus_type == NULL))
      return 0;

    /* Virus Scanner Output file */
    strsize = ((32 * sizeof(char)) + my_strlen(spool_dir) + 16);
    tmp_log = (char *) malloc(strsize + 1);
    if(bh_assert(tmp_log == NULL))
      return 0;
    snprintf(tmp_log, strsize+1,
             "%s/scanner/%i.%i.virus", spool_dir, (int) mytime, mypid);
    tmp_log[strsize] = (char)'\0';

#if VIRUS_SCANNER == CLAMSCAN
      if(bh_assert(mime_parse(tmp_file) == 1))
        return 0;
      if(mime_dir == NULL)
        return 0;
#endif

#ifdef CLAMSCAN_DAEMON
    if ((sockfd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
    {
      logging("Failed to create unix domain socket!");
      perror("socket()");
      rmdir_r(mime_dir);
      return 0;
    }

    /* setup the unix domain socket */
    memset(&address, 0, sizeof(address));

    address.sun_family = AF_LOCAL;
    strncpy(address.sun_path, CLAMSCAN_DAEMON_SOCKET, CLAMSCAN_DAEMON_SOCKET_LEN);

    /* connect to the clamscan daemon */
    if (connect(sockfd, (struct sockaddr *) &address, sizeof(address)) == -1)
    {
      logging("Failed to connect to ClamScan daemon at unix domain socket!");
      perror("connect()");
      close(sockfd);
      rmdir_r(mime_dir);
      return 0;
    }

    strncpy(clam_request, "SCAN ", sizeof(clam_request));
    strncat(clam_request, mime_dir, sizeof(clam_request) - strlen(clam_request));
    strncat(clam_request, "\n", sizeof(clam_request) - strlen(clam_request));

    /* request clamscan to scan the mime content */
    if (send(sockfd, (void *) clam_request, strlen(clam_request), 0) != strlen(clam_request))
    {
      logging("Failed to send SCAN request to clamscan daemon!");
      perror("send()");
      close(sockfd);
      rmdir_r(mime_dir);
      return 0;
    }

    /* read the results from clamscan daemon */
    while (1)
    {
      size = recv(sockfd, (void *) clam_request, sizeof(clam_request), 0);

      if (size == 0)
          break;
      else if (size == -1)
      {
          logging("Failed to read results from clamscan daemon!");
          perror("recv()");
          close(sockfd);
          rmdir_r(mime_dir);
          return 0;
      }

      /* sanity check for string terminiation */
      clam_request[sizeof(clam_request) - 1] = '\0';

      /* scan the result string for the FOUND keyword */
      if ((end = strstr(clam_request, "FOUND")) != NULL)
      {
          found_virus = 1;

          if (disinfect > 0)
              virus_status = 2;
          else
              virus_status = 1;

          /*
           * ClamScan reports messages in the following format:
             *   /path/to/file/message: OK
             *   /path/to/file/message: Phantom #1 FOUND
             *   /path/to/file/message: W32/Magistr.B FOUND
           *
           * The virus name can be reliabiliy found between : and FOUND
          */

          for (start = end; *start != ':' && start != &clam_request[0]; start--)
          {}

          /* align to whitespaces */
          start++;
          end--;

          /* copy the virus name */
          for (copy = ++start, loop = 0; copy != end; copy++, loop++)
              virus_type[loop] = *copy;

          virus_type[loop] = '\0';
      }
    }

    close(sockfd);

    if (found_virus == 0)
        free(virus_type);

    /* cleanup the MIME directory */
    rmdir_r(mime_dir);
  }

#else /* CLAMSCAN_DAEMON */

    /* Fork for Virus Scanner */
    pid = fork();
    if(bh_assert(pid == -1))
      return 0;

    if(pid == 0) {
#if VIRUS_SCANNER == MCAFEE
      char *mcafee_args[] = {
        uvscan,
#ifdef MCAFEE_ARGS
	MCAFEE_ARGS
#endif
        "--dat",
        dat_dir,
        tmp_file,
        '\0'
      };
#elif VIRUS_SCANNER == CLAMSCAN
      char *clamscan_args[] = {
        clamscan,
#ifdef CLAMSCAN_ARGS
	CLAMSCAN_ARGS
#endif
	mime_dir,
	'\0'
      };
#endif

      /* Redirect scanner output to a tmp file */
#if VIRUS_SCANNER == CLAMSCAN
      f = freopen(tmp_log, "w+", stderr);
#else 
      f = freopen(tmp_log, "w+", stdout);
#endif
      if(bh_assert(f == NULL)) {
        fprintf(stderr, "ERROR: Not able to open tmp file!\n");
        return 0;
      }

      /* Virus Scan the mime parts */
#if VIRUS_SCANNER == MCAFEE
      execv(uvscan, mcafee_args);
#elif VIRUS_SCANNER == CLAMSCAN
      execv(clamscan, clamscan_args);
#endif

      /* Error if still here */
      fprintf(stderr, "ERROR: Running the scanner failed!\n");
      exit(127);
    }
    do {
      if(waitpid(pid, &status, 0) == -1) {
        if(bh_assert(errno != EINTR)) {
          fprintf(stderr, "ERROR: Executing Scanner!\n");
          return -1;
        }
      } else {
        status >>= 8;
        status &= 0xFF;

        f = fopen(tmp_log, "r");
        if(bh_assert(f == NULL))
          return 0;

        /* Write Virus Scan results to file, then extract to variable */
#if VIRUS_SCANNER == MCAFEE
        if(status == 12 || status == 13 || status == 19) {
          int i, j;
          found_virus = 1;
          if(disinfect > 0)
            virus_status = 2;
          else
            virus_status = 1;
          rewind(f);
          while(fgets(line, MAX_INPUT_LINE + 1, f)) {
            if(!strncmp(line, "        Found", 13)) {
              my_strlcpy(virus_type, line, my_strlen(line)+1);
              break;
            }
          }
          for(i = 18, j = 0;
              virus_type[i] != '\0' && virus_type[i] != '\n'; i++) {
            if(virus_type[i] != ' ') {
              virus_type[j++] = virus_type[i];
            } else
              break;
          }
          virus_type[j] = '\0';
        } else
          free(virus_type);

#elif VIRUS_SCANNER == CLAMSCAN
        if(status == 1) {
          int i, j;
          status = 12;
          rewind(f);
          while(fgets(line, MAX_INPUT_LINE + 1, f)) {
            if(strstr(line, "FOUND") != NULL) {
              found_virus = 1;
              if(disinfect > 0)
                virus_status = 2;
              else
                virus_status = 1;
              for(i=0;line[i] != '\0' && line[i] != ' ';i++);
              for(j=0,i++;line[i] != '\0' && line[i] != ' ';j++,i++)
                virus_type[j] = line[i];
              virus_type[j] = '\0';
              break;
            }
          }
        } else if(status == 0) {
          /* OK and no virus */
          free(virus_type);
        } else {
          if(DEBUG)
            fprintf(stderr, "ERROR: Running ClamScan Scanner, returned (%d)!\n",
                 status);
          free(virus_type);
        }
        /* Remove temporary directory used for MIME Parsing */
        rmdir_r(mime_dir);

#endif
        /* Clean up memory and tmp files */
        fclose(f);
        unlink(tmp_log);
        free(tmp_log);
        free(line);

#if WITH_DEBUG == 1
        if(DEBUG) {
          fprintf(stderr, "Virus Status: [");
          if(status == 0)
            fprintf(stderr, "File is Clean]\n");
          else if(status == 12 || status == 13)
            fprintf(stderr, "Virus found]\n");
          else if(status == 19)
            fprintf(stderr, "Virus found and Cleaned]\n");
          else
            fprintf(stderr, "ERROR with scanner (%d)]\n", status);
        }
#endif
        break;
      }
    } while(1);
  }

#endif /* CLAMSCAN_DAEMON */

  /* Return virus code if found, else Clean */
  return virus_status;
}

int get_file_size(char *filename)
{
  struct stat buf;

  if(stat(filename, &buf) == 0) {
    if(buf.st_size == 0)
      return buf.st_size;
  }
  return -1;
}
