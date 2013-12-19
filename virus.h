/* virus.h */
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
#ifndef _VIRUS_H
#define _VIRUS_H 1

#ifndef USE_MCONFIG
#include "config.h"
#endif

#ifndef SOPHOS_RIPMIME
#define SOPHOS_RIPMIME 1
#endif

/* CLAMSCAN ARGS */
#ifndef CLAMSCAN_ARGS
#define CLAMSCAN_ARGS \
	"--unzip=/usr/bin/unzip", \
	"--tar=/bin/tar",
#endif
/* These are the current options...
                   Clam Antivirus: The Scanner (ClamScan)  0.22
                   (c) 2002 Tomasz Kojm <zolw@konarski.edu.pl>

    --help                  -h          show help
    --version               -V          print version number and exit
    --verbose               -v          be verbose
    --quiet                             be quiet, output only error messages
    --stdout                            write to stdout instead of stderr
                                        (this help is always written to stdout)
    --force                             try to ignore some errors

    --tempdir DIRECTORY                 create temporary files in DIRECTORY
    --database  FILE        -d FILE     read virus database from FILE
    --log FILE              -l FILE     save scan report in FILE
    --log-verbose                       save additional informations
    --recursive             -r          scan directories recursively
    --infected              -i          print infected files only
    --disable-summary                   disable summary at end of scanning

    --max-space #n                      extract first #n kilobytes only
    --max-files #n                      extract first #n files only
    --unzip[=FULLPATH]                  enable support for .zip files
    --unrar[=FULLPATH]                  enable support for .rar files
    --unace[=FULLPATH]                  enable support for .ace files
    --unarj[=FULLPATH]                  enable support for .arj files
    --zoo[=FULLPATH]                    enable support for .zoo files
    --lha[=FULLPATH]                    enable support for .lha files
    --jar[=FULLPATH]                    enable support for .jar files
    --tar[=FULLPATH]                    enable support for .tar files
    --tgz[=FULLPATH]                    enable support for .tar.gz, .tgz files

    --threads #n                        use n threads
*/

/* McAfee Args */
#ifndef MCAFEE_ARGS
#define MCAFEE_ARGS \
	"--unzip", \
        "--exit-on-error", \
        "--noboot", \
        "--norename", \
        "--noexpire", \
        "--ignore-links", \
        "--mime", 
#endif

#define MCAFEE 1
#define SOPHOSSDK 2
#define TRENDMICRO 3
#define CLAMSCAN 4 

/* #define CLAMSCAN_DAEMON */
/* #define CLAMSCAN_DAEMON_SOCKET "/path_to_clamscan_daemon_socket" */

#endif /* _VIRUS_H */
