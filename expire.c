/* exipire.c */
static char *id = 
     "$Id: expire.c,v 1.25 2002/08/08 20:08:07 bitbytebit Exp $";
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
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "my_string.h"
#include "max.h"
#include "misc.h"

extern int DEBUG;

extern char *homedir;
extern char *maildir;
extern char *hostname;

int get_file_tstamp(char *);

int expire(char *folder, char *subfolder, int days)
{
  DIR *d;
  struct dirent *dir;
  char *message;
  char *directory;
  int file_age;
  time_t now;
  char *exp_lock = ".bh_expire";
  char *exp_lock_link;
  pid_t pid;
  FILE *lck;

  /* get current UNIX time and PID */
  time(&now);
  pid = getpid();

  strsize = my_strlen(exp_lock) + my_strlen(hostname) + 23;
  exp_lock_link = malloc(strsize + 1);
  if(bh_assert(exp_lock_link == NULL))
    return 1;
  
  snprintf(exp_lock_link, strsize + 1,
           "%s.%d.%d.%s", exp_lock, (int) now, pid, hostname);
  exp_lock_link[strsize] = (char)'\0';

  lck = fopen(exp_lock_link, "w");
  if(bh_assert(lck == NULL))
    return 1;

  /* try linking lock file */
  if(link(exp_lock_link, exp_lock) != 0) {
    fclose(lck);
    unlink(exp_lock_link);
    return 1;
  }

  /* See if maildir is in homedir or global */
  if(strncmp(maildir, "/", 1) == 0) {
    strsize = my_strlen(maildir) + my_strlen(folder) + my_strlen(subfolder) + 2;
    directory = malloc(strsize + 1);
    if(bh_assert(directory == NULL)) {
      unlink(exp_lock);
      fclose(lck);
      unlink(exp_lock_link);
      return 1;
    }
    snprintf(directory, strsize + 1,
             "%s/%s/%s", maildir, folder, subfolder);
    directory[strsize] = (char)'\0';
  } else {
    strsize = my_strlen(homedir) + my_strlen(maildir) + my_strlen(folder) +
             my_strlen(subfolder) + 3;
    directory = malloc(strsize + 1);
    if(bh_assert(directory == NULL)) {
      unlink(exp_lock);
      fclose(lck);
      unlink(exp_lock_link);
      return 1;
    }
    snprintf(directory, strsize + 1,
             "%s/%s/%s/%s", homedir, maildir, folder, subfolder);
    directory[strsize] = (char)'\0';
  }

  /* open up directory */
  d = opendir(directory);
  if(bh_assert(d == NULL)) {
    fprintf(stderr, "%s: Not able to open dir %s!\n", __FILE__, directory);
    unlink(exp_lock);
    fclose(lck);
    unlink(exp_lock_link);
    return 1;
  }

  /* Loop for each message */
  while((dir = readdir(d)) != NULL) {
    if(strncmp(dir->d_name, ".", 1) == 0)
      continue;

    /* Message File */
    strsize = my_strlen(directory) + (sizeof(dir->d_name) * sizeof(char)) + 1;
    message = malloc(strsize + 1);
    if(bh_assert(message == NULL)) {
      unlink(exp_lock);
      fclose(lck);
      unlink(exp_lock_link);
      return 1;
    }
    snprintf(message, strsize + 1,
             "%s/%s", directory, dir->d_name);

    /* Check timestamp of file against days given to expire */
    file_age = get_file_tstamp(message);
    file_age = now - file_age;
    file_age = file_age / 60 / 60 / 24;

    /* Skip if less than expire days old */
    if(file_age < days)
      continue;

    if(DEBUG)
      fprintf(stderr, "Removing %d day old file %s\n", file_age, message);

    /* unlink file if greater than days to expire */
    unlink(message);
    free(message);
  }
  closedir(d);
  free(directory);

  unlink(exp_lock);
  fclose(lck);
  unlink(exp_lock_link);
  free(exp_lock_link);
  return 0;
}

int get_file_tstamp(char *filename)
{
  struct stat buf;

  if(stat(filename, &buf) == 0) {
    if(buf.st_mtime != 0)
      return buf.st_mtime;
  }
  return -1;
}
