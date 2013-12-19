/* tmicro.h */
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
/* 
 Code template taken from Vanja Hrustic (vanja@pobox.com)
 Trophie Author, who did the reverse engineering of Trend Micros Library
*/

int vs_ret;
int vs_addr;

#define VS_PROCESS_ALL_FILES_IN_ARCHIVE         1
#define VS_PROCESS_ALL_FILES                    1

struct vs_type
{
  int handle_addr;
  int vs_pid;
  char vscan_str[9];
  char version_string[11];
  unsigned short pattern_version;
  unsigned short unknown_1;
  unsigned long pattern_number;
};
struct vs_type tmicro_vs;

/* For callbackup function */
struct callback_type
{
  int flag_infected;
  int flag_archive;
  int so_far_it_was_always_minus_one;
  char *archive_being_scanned;
  char this_is_how_windows_source_code_looks_like[156];
  char *vname;
  char *current_filename;
};

int tinit(void);
void tclose(void);
int tscan(char *);
int vs_virus_scan_file_callback_function(char *a, struct callback_type *b,
                                         int c, char *d);
int extract(char *a);
int VSVirusScanFileWithoutFNFilter(int, char *, int);
int VSInit(pid_t, char *, int, int *);
int VSReadVirusPattern(int, int, int, int);
int VSGetVSCInfo(struct vs_type *);
int (VSSetProcessFileCallBackFunc) ();
int VSSetProcessAllFileInArcFlag(int, int);
int VSSetProcessAllFileFlag(int, int);
int VSQuit(int);
