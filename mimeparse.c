/* mimeparse.c */
static char *id = 
     "$Id: mimeparse.c,v 1.16 2002/10/15 18:39:24 bitbytebit Exp $";
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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

#ifndef USE_MCONFIG
#include "config.h"
#endif
#include "virus.h"

#if VIRUS_SCANNER == CLAMSCAN || (SOPHOS_RIPMIME == 1 && VIRUS_SCANNER == SOPHOSSDK)

#include "ripmime/mime.h"
#include "ripmime/tnef/tnef_api.h"
#include "ripmime/MIME_headers_api.h"

int rip_mime(char *, char *);
int rmdir_r(char *);

#include "misc.h"
#include "max.h"
#include "my_string.h"

extern char *spool_dir;
extern char *fname;
extern char *tmp_file;
extern char *mime_dir;

int mime_parse(char *file) {
  if(bh_assert(file == NULL))
    return 1;

  /* Directory to break mime into */
  strsize = (my_strlen(fname) + my_strlen(spool_dir) + 6);
  mime_dir = malloc(strsize + 1);
  if(bh_assert(mime_dir == NULL))
    return 1;

  snprintf(mime_dir, strsize+1,
           "%s/mime/%s", spool_dir, fname);
  mime_dir[strsize] = (char)'\0';

  /* Create directory */
#ifdef CLAMSCAN_DAEMON
  if(bh_assert(mkdir(mime_dir, 0755) != 0))
#else
  if(bh_assert(mkdir(mime_dir, 0700) != 0))
#endif
    return 1;

  /* Populate directory with the mime parts through ripmime's API */
  if(bh_assert(rip_mime(mime_dir,tmp_file) != 0))
    return 1;

  return 0;
}

/* Ripmime API */
int rip_mime(char *vdir, char *vfile) {
  MIMEH_set_outputdir(vdir);
  MIME_init();
  MIME_unpack(vdir, vfile, 0);
  //MIME_close();
        
  return 0;
}

/* Remove files recursively */
int rmdir_r(char *directory) {
  DIR *d;
  struct dirent *dir;
  char *message;

  if(bh_assert(directory == NULL))
    return 1;
  
  d = opendir(directory);
  if(bh_assert(d == NULL)) {
    fprintf(stderr, "%s: Not able to open dir %s!\n", __FILE__, directory);
    return 1;
  }
 
  while((dir = readdir(d)) != NULL) {
    if((strcmp(dir->d_name, ".") == 0) || (strncmp(dir->d_name, "..", 2) == 0))
      continue;

    /* Message File */
    strsize = my_strlen(directory) + (sizeof(dir->d_name) * sizeof(char)) + 1;
    message = malloc(strsize + 1);
    if(bh_assert(message == NULL))
      return 1;
    snprintf(message, strsize + 1,
             "%s/%s", directory, dir->d_name);

    unlink(message);
    free(message);
  } 
  closedir(d);
  rmdir(directory);
 
  return 0;
}

#endif

