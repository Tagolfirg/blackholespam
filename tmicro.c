/* tmicro.c */
static char *id = 
     "$Id: tmicro.c,v 1.10 2002/08/08 20:08:07 bitbytebit Exp $";
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
/* Code template taken from Vanja Hrustic (vanja@pobox.com)
 Trophie Author, who did the reverse engineering of Trend Micros Library
*/
#ifndef USE_MCONFIG
#include "config.h"
#endif

#include "virus.h"

#if VIRUS_SCANNER == TRENDMICRO
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "tmicro.h"

#include "max.h"
#include "my_string.h"

extern int DEBUG;
extern char *virus_type;
extern int found_virus;

int tmicro(char *tmp_file)
{
  int vsapi_r;

  if(tinit() != 0) {
    fprintf(stderr, "Failed starting\n");
    return 1;
  }
  vsapi_r = tscan(tmp_file);
  tclose();

#if WITH_DEBUG == 1
  if(found_virus != 0 && virus_type != NULL)
    if(DEBUG)
      fprintf(stderr, "Virus: %s found!\n", virus_type);
#endif

  return 0;
}

int tscan(char *file)
{
  vs_ret = VSVirusScanFileWithoutFNFilter(vs_addr, file, -1);

  if(vs_ret == -89)
    vs_ret = 0;

  return vs_ret;
}

int tinit(void)
{
  if((vs_ret = VSInit(getpid(), "VSCAN", -1, &vs_addr)) != 0) {
    fprintf(stderr, "ERROR: VSInit() failed (return code: [%d])\n", vs_ret);
    return 1;
  }

  if((vs_ret = VSReadVirusPattern(vs_addr, -1, 0, 0)) != 0) {
    fprintf(stderr, "VSReadVirusPattern() failed (return code: [%d])\n",
            vs_ret);
    return 1;
  }

  tmicro_vs.handle_addr = vs_addr;
  tmicro_vs.version_string[0] = 0;

  if((vs_ret = VSGetVSCInfo(&tmicro_vs)) != 0) {
    fprintf(stderr, "VSGetVSCInfo() failed (return code: [%d])\n", vs_ret);
    return 1;
  }

  if((vs_ret =
      VSSetProcessFileCallBackFunc(vs_addr,
                                   &vs_virus_scan_file_callback_function)) !=
     0) {
    fprintf(stderr,
            "VSSetProcessFileCallBackFunc() failed (return code: [%d]\n",
            vs_ret);
    return 1;
  }

  VSSetProcessAllFileInArcFlag(vs_addr, 1);
  VSSetProcessAllFileFlag(vs_addr, 1);

  return 0;
}

void tclose(void)
{
  VSQuit(vs_addr);
}

int vs_virus_scan_file_callback_function(char *a, struct callback_type *b,
                                         int c, char *d)
{
  if((c == 1) && b->flag_infected > 0) {
    char *virus_name = (char *) (b->vname + 8);
    strsize = my_strlen(virus_name);
    virus_type = malloc(strsize + 1);
    my_strlcpy(virus_type, virus_name, strsize+1);
    found_virus = 1;

    if(DEBUG)
      fprintf(stderr, "scanning file: '%s'\n", b->current_filename);

    if(DEBUG)
      fprintf(stderr, "Infected with '%s' virus\n", virus_type);
  }
  return (0);
}

int extract(char *a)
{
  return (0);
}
#endif
