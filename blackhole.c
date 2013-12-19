/* blackhole.c */
static char *id = 
     "$Id: blackhole.c,v 1.420 2003/01/10 14:14:48 bitbytebit Exp $";
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
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "blackhole.h"

/* this programs name */
char *progname = NULL;
char *rcptto = NULL, *hostrelay = NULL, *subject = NULL, *charset = NULL;
char *iprelay = NULL, *mailfrom = NULL;

int main(int argc, char *argv[])
{
  int i, j;
  int maxlevel = 0, excluded_ip = 0;
  int found_mailfrom = 0, found_rcptto = 0;
  int found_ip = 0, found_sub = 0, found_charset = 0, found_body = 0;
  int body_check_match = 0, ascii_128_match = 0, header_match = 0;
  int ctype_match = 0, encoding_match = 0, maxsize_match = 0, attach_match = 0;
  char *line = NULL;
  struct utsname unamestruct;
  struct passwd *pwd;
  time_t tstamp;
  pid_t pid;
  FILE *debug_fp;

#ifdef ENABLE_COREDUMP
  enable_core();
#endif

  /* program name */
  if((progname = strrchr(argv[0], '/')) != NULL)
    progname++;
  else
    progname = argv[0];

#ifndef QMAIL_QFILTER
  /* Set umask */
  umask(077);
#else
  umask(027);
#endif

  /* Lower priority if set */
  if(priority > 0)
    setpriority(PRIO_PROCESS, 0, priority);

  /* stringify the version numbers */
  strsize = (typlen(MAJOR_VERSION) + typlen(MINOR_VERSION) +
             typlen(MINOR_REVISION) + 2);
  version = (char *) malloc(strsize + 1);
  if(bh_assert(version == NULL))
    bh_exit(DEFER);
  snprintf(version, strsize, "%d.%d.%d",
           MAJOR_VERSION, MINOR_VERSION, MINOR_REVISION);
  version[strsize] = (char) '\0';

  /* Get users home dir */
  if(bh_assert((pwd = getpwuid(getuid())) == NULL))
    bh_exit(DEFER);

  /* Try the environment first */
  if(getenv("HOME") != NULL) {
    homedir = malloc(MAX_HOMEDIR_SIZE + 1);
    my_strlcpy(homedir, (char *) getenv("HOME"), MAX_HOMEDIR_SIZE + 1);
    homedir[MAX_HOMEDIR_SIZE] = (char) '\0';
  } else {
    strsize = my_strlen(pwd->pw_dir);
    homedir = malloc(strsize + 1);
    if(bh_assert(homedir == NULL))
      bh_exit(DEFER);
    my_strlcpy(homedir, pwd->pw_dir, strsize + 1);
  }

  /* Get username */
  strsize = my_strlen(pwd->pw_name);
  username = malloc(strsize + 1);
  if(bh_assert(username == NULL))
    bh_exit(DEFER);
  my_strlcpy(username, pwd->pw_name, strsize + 1);

  /* Close password file */
  endpwent();

  /*******************************/
  /* Read the Configuration File */
  /*******************************/
  if(bh_assert(readconfig(RC_GLOBAL) == 1))
    fprintf(stderr, "%s: ERROR: reading global config!\n", progname);

  if(argc > 2 && argv[2][0] == '/') {
    /* cmdline config */
  } else if(qmail_queue == 0 && pfilter == 0)
    readconfig(RC_OVERWRITEOFF);

  /* Get Max Level */
  for(i = 0; rblhosts[i] != NULL; i++)
    maxlevel = i;

  /*******************/
  /* Check Arguments */
  /*******************/
  if(argc > 1) {
    for(i = 1; argv[i] && (i <= argc); i++) {
      if((strncmp(argv[i], "-", 1) == 0
         && (my_strlen(argv[i]) == 1))) {
        usage_err(maxlevel);
        bh_exit(DEFER);
      } else if((strncmp(argv[i], "-", 1) == 0) && (argv[i][1] == '\0'))
        continue;
      else if(strncmp(argv[i], "/", 1) == 0) {
        /* Cmdline Config location */
        strsize = my_strlen(argv[i]);
        config_file = malloc(strsize + 1);
        if(config_file == NULL)
          continue;
        my_strlcpy(config_file, argv[i], strsize + 1);
        if(bh_assert(readconfig(RC_USER) == 1)) {
          fprintf(stderr, "%s: ERROR: reading cmdline config!\n", progname);
          bh_exit(DEFER);
        }
        continue;
      }

      if(!cmd_cmp(argv[i], "-debug", 2)) {
        DEBUG = 1;
        if(i < (argc - 1) && strncmp(argv[i + 1], "-", 1)) {
          debug_fp = freopen(argv[i + 1], "a", stderr);
          if(debug_fp == NULL)
            fprintf(stderr, "%s\n",
                    "ERROR: opening/appending debugging logfile!");
          i++;
        }
        continue;
      } else if(!cmd_cmp(argv[i], "-InternalSettings", 2)) {
        internal_settings();
        exit(0);
      } else if(!cmd_cmp(argv[i], "-help", 2)) {
        usage_err(maxlevel);
        exit(0);
      } else if(!cmd_cmp(argv[i], "-version", 2)) {
        fprintf(stderr, 
            "BlackHole Version %s (C) Chris Kennedy 2002.\n", version);
        exit(0);
      } else if(!cmd_cmp(argv[i], "-bounce", 2)) {
        bouncemsg = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-config", 2)) {
        /* List the Configuration File */
        if(readconfig(RC_SHOW) == 1)
          fprintf(stderr, "%s: ERROR: reading config!\n", progname);
        exit(0);
      } else if(!cmd_cmp(argv[i], "-setup", 3)) {
        /* Config Parser */
        cfg_int = 1;
        readconfig(RC_USER);
        config();
        exit(0);
      } else if(!cmd_cmp(argv[i], "-razor", 2)) {
        userazor = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-pyzor", 2)) {
        usepyzor = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-list", 2)) {
        /* Show RBL Lists and Exit */
        printf("Current RBL Lists:\n\n");
        for(i = 0; rblhosts[i] != NULL; i++)
          printf(" (%d). %s\n", i, rblhosts[i]);
        exit(0);
      } else if(!cmd_cmp(argv[i], "-oklog", 4) ||
	!cmd_cmp(argv[i], "-log_ok", 5)) {
        log_ok = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-log_score", 7)) {
        log_score = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-log_size", 7)) {
        log_size = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-log_iprelay", 6)) {
        log_iprelay = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-log_sender", 6)) {
        log_sender = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-log_recipient", 6)) {
        log_recipient = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-log", 3)) {
        use_log = 1;
        if(i < (argc - 1) && strncmp(argv[i + 1], "-", 1)) {
          if(strncmp(argv[i + 1], "stderr", my_strlen(argv[i + 1])) == 0)
            log_type = error;
#if WITH_SQL == 1
          else if(strncmp(argv[i + 1], "sql", my_strlen(argv[i + 1])) == 0 ||
                  strncmp(argv[i + 1], "mysql", my_strlen(argv[i + 1])) == 0 ||
                  strncmp(argv[i + 1], "pgsql", my_strlen(argv[i + 1])) == 0)
            log_type = sql;
#endif
          else if(strncmp(argv[i + 1], "syslog", my_strlen(argv[i + 1])) == 0)
            log_type = syslog;
          else if(strncmp(argv[i + 1], "stdout", my_strlen(argv[i + 1])) == 0)
            log_type = output;
          else {
            usage_err(maxlevel);
#ifdef WITH_BH_ASSERT
            bh_assert(1);
#endif
            fprintf(stderr, "%s: ERROR: bad log type given!\n", progname);
            bh_exit(DEFER);
          }
          i++;
        }
        continue;
      } else if(!cmd_cmp(argv[i], "-Sendmail", 2)) {
        sendmail = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-Resolve", 4)) {
        check_sender = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-Reverse", 4)) {
        checkreverse = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-SReverse", 3)) {
        checkhelo = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-Whitelist", 2)) {
        white_list = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-Level", 2)) {
        /* Show MAX and CURRENT RBL levels and Exit */
        printf("Maximum: %d\n", maxlevel);
        printf("Current: %d\n", level);
        exit(0);
      } else if(!cmd_cmp(argv[i], "-total", 2)) {
        STOP_WHEN_FOUND = 0;
        continue;
      } else if(!cmd_cmp(argv[i], "-Clean", 2)) {
        disinfect = 1;
        continue;
      /** Added by: Joe Stump <joe@joestump.net> **/
      } else if(!cmd_cmp(argv[i], "-stdout", 2)) {
        send_to_stdout = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-Virus", 2)) {
        virusscan = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-VDelete", 3)) {
        virus_delete = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-Alert", 2)) {
        virus_alert = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-norbl", 4)) {
        spam_scan = 0;
        continue;
      } else if(!cmd_cmp(argv[i], "-nosignature", 4)) {
        nosignature = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-Queue", 2)) {
        qmail_queue = 1;
        continue;
#ifdef HAVE_LIBPCRE
      } else if(!cmd_cmp(argv[i], "-BSpam", 3)) {
        BODY_SCAN = 1;
        SPAM_BODY = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-BPorn", 3)) {
        BODY_SCAN = 1;
        PORN_BODY = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-BRacist", 3)) {
        BODY_SCAN = 1;
        RACIST_BODY = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-BCustom", 3)) {
        BODY_SCAN = 1;
        MY_BODY = 1;
        continue;
#endif
      } else if(!cmd_cmp(argv[i], "-maildir", 2)) {
        use_maildir = 1;
        if(i < (argc - 1) && strncmp(argv[i + 1], "-", 1)) {
          strsize = my_strlen(argv[i + 1]);
          maildir = malloc(strsize + 1);
          if(bh_assert(maildir == NULL))
            bh_exit(DEFER);
          my_strlcpy(maildir, argv[i + 1], strsize + 1);
          i++;
        } else {
          usage_err(maxlevel);
#ifdef WITH_BH_ASSERT
          bh_assert(1);
#endif
          fprintf(stderr, "%s: ERROR: no maildir given!\n", progname);
          bh_exit(DEFER);
        }
        continue;
      } else if(!cmd_cmp(argv[i], "-Nameserver", 2)) {
        if(i < (argc - 1) && strncmp(argv[i + 1], "-", 1)) {
          strsize = my_strlen(argv[i + 1]);
          dns_srv = malloc(strsize + 1);
          if(bh_assert(dns_srv == NULL))
            bh_exit(DEFER);
          my_strlcpy(dns_srv, argv[i + 1], strsize + 1);
          i++;
        } else {
          usage_err(maxlevel);
#ifdef WITH_BH_ASSERT
          bh_assert(1);
#endif
          fprintf(stderr, "%s: ERROR: no DNS Server IP given!\n", progname);
          bh_exit(DEFER);
        }
        continue;
      } else if(!cmd_cmp(argv[i], "-spool", 2)) {
        SPOOLDIR = 1;
        if(i < (argc - 1) && strncmp(argv[i + 1], "-", 1)) {
          strsize = my_strlen(argv[i + 1]);
          spooldir = malloc(strsize + 1);
          if(bh_assert(spooldir == NULL))
            bh_exit(DEFER);
          my_strlcpy(spooldir, argv[i + 1], strsize + 1);
          i++;
        } else {
          usage_err(maxlevel);
#ifdef WITH_BH_ASSERT
          bh_assert(1);
#endif
          fprintf(stderr, "%s: ERROR: no spooldir given!\n", progname);
          bh_exit(DEFER);
        }
        continue;
      } else if(!cmd_cmp(argv[i], "-Delete", 2)) {
        store_email = 0;
        continue;
      } else if(!cmd_cmp(argv[i], "-Onebox", 2)) {
        allinone = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-HAscii", 2)) {
        CHAR_128 = 1;
        /* Max before Spam */
        if(i < (argc - 1) && strncmp(argv[i + 1], "-", 1)) {
          for(j = 0; argv[i + 1][j] != '\0'; j++) {
            if(bh_assert(isdigit(argv[i + 1][j]) == 0)) {
              /* Bad Argument Given */
              usage_err(maxlevel);
              fprintf(stderr, "%s: ERROR: bad option! %s\n",
                      progname, argv[i + 1]);
              bh_exit(DEFER);
            }
          }
          max_ascii_score = (int) atoi(argv[i + 1]);
          i++;
        } else {
          usage_err(maxlevel);
#ifdef WITH_BH_ASSERT
          bh_assert(1);
#endif
          fprintf(stderr, "%s: ERROR: no char128 amount given!\n", progname);
          bh_exit(DEFER);
        }
        continue;
      } else if(!cmd_cmp(argv[i], "-Expire", 2)) {
        /* Max days before Expire */
        if(i < (argc - 1) && strncmp(argv[i + 1], "-", 1)) {
          for(j = 0; argv[i + 1][j] != '\0'; j++) {
            if(bh_assert(isdigit(argv[i + 1][j]) == 0)) {
              /* Bad Argument Given */
              usage_err(maxlevel);
              fprintf(stderr, "%s: ERROR: bad option! %s\n",
                      progname, argv[i + 1]);
              bh_exit(DEFER);
            }
          }
          expire_time = (int) atoi(argv[i + 1]);
          i++;
        } else {
          usage_err(maxlevel);
#ifdef WITH_BH_ASSERT
          bh_assert(1);
#endif
          fprintf(stderr, "%s: ERROR: no expire time given!\n", progname);
          bh_exit(DEFER);
        }
        continue;
#if WITH_SQL == 1
      } else if(!cmd_cmp(argv[i], "-SQL", 3) || !cmd_cmp(argv[i], "-MySQL", 2)){
        sqlconfig = 1;
        /* SQL Host */
        if(i < (argc - 1) && strncmp(argv[i + 1], "-", 1)) {
          strsize = my_strlen(argv[i + 1]);
          sql_host = malloc(strsize + 1);
          if(bh_assert(sql_host == NULL))
            bh_exit(DEFER);
          my_strlcpy(sql_host, argv[i + 1], strsize + 1);
          i++;
        }
        continue;
#endif
      } else if(!cmd_cmp(argv[i], "-Pfilter", 2)) {
        int x = 3;
        pfilter = 1;
        allinone = 1;
        sendmail = 1;

        /* should be {sender} {recipient}..., although maybe just {recpient} */
        if(argv[i + 1] != '\0') {
          if(argv[i + 2] != '\0') {
            /* 2 args given */
            while(i < (argc - 1)) {
              strsize = my_strlen(argv[i + 1]);
              pfilter_args[x] = malloc(strsize + 1);
              if(bh_assert(pfilter_args[x] == NULL))
                bh_exit(DEFER);
              my_strlcpy(pfilter_args[x], argv[i + 1], strsize + 1);
#if WITH_DEBUG == 1
              if(DEBUG)
                fprintf(stderr, "%d). %s\n", i + 1, pfilter_args[x]);
#endif
              i++;
              x++;
            }
          } else {
            /* 1 arg given */
            /* so fake sender */
            strsize = strlen("mailer-daemon");
            pfilter_args[x] = malloc(strsize + 1);
            if(bh_assert(pfilter_args[x] == NULL))
              bh_exit(DEFER);
            my_strlcpy(pfilter_args[x], "mailer-daemon", strsize + 1);
#if WITH_DEBUG == 1
            if(DEBUG)
              fprintf(stderr, "%d). %s\n", x, pfilter_args[x]);
#endif
            x++;
            /* recipient */
            if(i >= (argc - 1))
              continue;
            strsize = my_strlen(argv[i + 1]);
            pfilter_args[x] = malloc(strsize + 1);
            if(bh_assert(pfilter_args[x] == NULL))
              bh_exit(DEFER);
            my_strlcpy(pfilter_args[x], argv[i + 1], strsize + 1);
#if WITH_DEBUG == 1
            if(DEBUG)
              fprintf(stderr, "%d). %s\n", x, pfilter_args[x]);
#endif
            i++;
            i++;
            x++;
          }  
          pfilter_args[x] = malloc(1); 
          if(bh_assert(pfilter_args[x] == NULL))
            bh_exit(DEFER);
          pfilter_args[x] = '\0';
        } else {
#ifdef WITH_BH_ASSERT
          bh_assert(1);
#endif
          fprintf(stderr,"ERROR: no arguments given to -Pf!\n");
          bh_exit(DEFER);
        }

        /* Get Sender and Recipient */
        if(pfilter_args[3] != NULL) {
          /* Get the Sender */
          mailfrom = malloc(MAX_EMAIL_SIZE + 1);
          if(bh_assert(mailfrom == NULL))
            bh_exit(DEFER);

          my_strlcpy(mailfrom, (char *) pfilter_args[3], MAX_EMAIL_SIZE + 1);
          mailfrom[MAX_EMAIL_SIZE] = (char) '\0';
          found_mailfrom = 1;

          if(pfilter_args[4] != NULL) {
            /* Get the Recipient */
            rcptto = malloc(MAX_EMAIL_SIZE + 1);
            if(bh_assert(rcptto == NULL))
              bh_exit(DEFER);

            my_strlcpy(rcptto, (char *) pfilter_args[4], MAX_EMAIL_SIZE + 1);
            rcptto[MAX_EMAIL_SIZE] = (char) '\0';
            found_rcptto = 1;
          }
        }
        i++;
#if WITH_DEBUG
        if(DEBUG) {
          int d = 0;
          for(d = 0;pfilter_args[d] != NULL;d++)
            fprintf(stderr, "PFILTER ARG %d: %s\n", d, pfilter_args[d]);
          fprintf(stderr, "PFILTER STATE: i = %d, x = %d\n", i, d);
        }
#endif
        continue;
      } else if(!cmd_cmp(argv[i], "-Maxscore", 3)) {
        /* Maxscore */
        if(i < (argc - 1) && strncmp(argv[i + 1], "-", 1)) {
          for(j = 0; argv[i + 1][j] != '\0'; j++) {
            if(bh_assert(isdigit(argv[i + 1][j]) == 0)) {
              /* Bad Argument Given */
              usage_err(maxlevel);
              fprintf(stderr, "%s: ERROR: bad option! %s\n",
                      progname, argv[i + 1]);
              bh_exit(DEFER);
            }
          }
          maxscore = (int) atoi(argv[i + 1]);
          i++;
        } else {
          usage_err(maxlevel);
#ifdef WITH_BH_ASSERT
          bh_assert(1);
#endif
          fprintf(stderr, "%s: ERROR: no maxscore given!\n", progname);
          bh_exit(DEFER);
        }
        continue;
      } else {
        /* Get level from command line */
        for(j = 0; argv[i][j] != '\0'; j++) {
          if(bh_assert(isdigit(argv[i][j]) == 0)) {
            /* Bad Argument Given */
            usage_err(maxlevel);
            fprintf(stderr, "%s: ERROR: bad option! %s\n", progname, argv[i]);
            bh_exit(DEFER);
          }
        }
        level = (int) atoi(argv[i]);
      }
    }
  }

  /* Check for root user */
  if(getuid() == 0) {
    if(DEBUG) {
      fprintf(stderr, "*******************************************\n");
      fprintf(stderr, "WARNING: running blackhole as the root user\n");
      fprintf(stderr, "is not recommended or supported!!!\n");
      fprintf(stderr, "*******************************************\n");
    }
  }

  /* Set level to max if more than max given */
  if(level > maxlevel)
    level = maxlevel;

  timestamp = malloc(64 + 1);
  if(bh_assert(timestamp == NULL))
    bh_exit(DEFER);

  /* Get timestamp */
  time_stamp(timestamp);

  /* Get the Hostname */
  uname(&unamestruct);
  if(unamestruct.nodename != NULL) {
    strsize = my_strlen(unamestruct.nodename);
    hostname = malloc(strsize + 1);
    if(bh_assert(hostname == NULL))
      bh_exit(DEFER);
    my_strlcpy(hostname, unamestruct.nodename, strsize + 1);
  }

  /* Time and Pid for Filename */
  time(&tstamp);
  pid = getpid();

#if WITH_SQL == 1
  /***********************/
  /* SQL Database config */
  /***********************/
  if(sqlconfig == 1 && qmail_queue == 0 && pfilter == 0) {
#if WITH_DEBUG == 1
    if(DEBUG)
      fprintf(stderr, "Using SQL, config file is %s\n", config_file);
#endif
    i = sql_config();
    if(i == 0 && DEBUG)
      fprintf(stderr, "%s %s %s Updated local config with SQL DB\n",
              timestamp, hostname, username);
  }
#endif

  /* for input line storage */
  line = malloc(MAX_INPUT_LINE + 1);
  if(bh_assert(line == NULL))
    bh_exit(DEFER);

  /* ip relay (ipv4 for now) */
  iprelay = malloc(MAX_RELAY_SIZE + 1);
  if(bh_assert(iprelay == NULL))
    bh_exit(DEFER);
  iprelay[0] = '\0';

  /* host relay */
  if(check_reverse > 0) {
    hostrelay = malloc(MAX_INPUT_LINE + 1);
    if(bh_assert(hostrelay == NULL))
      bh_exit(DEFER);
    hostrelay[0] = '\0';
  }

  /* tmp file */
  strsize = (my_strlen(hostname) + 20 + 2);
  fname = (char *) malloc(strsize + 1);
  if(bh_assert(fname == NULL))
    bh_exit(DEFER);
  snprintf(fname, strsize + 1, "%i.%i.%s", (int) tstamp, pid, hostname);
  fname[strsize] = (char) '\0';

  /* full path to tmp file */
  strsize = (my_strlen(fname) + my_strlen(spool_dir) + 9);
  tmp_file = (char *) malloc(strsize + 1);
  if(bh_assert(tmp_file == NULL))
    bh_exit(DEFER);
  snprintf(tmp_file, strsize + 1, "%s/msg/tmp/%s", spool_dir, fname);
  tmp_file[strsize] = (char) '\0';

  /**********************************/
  /* Open TMP File to store message */
  /**********************************/
#if WITH_DEBUG == 1
  if(DEBUG)
    fprintf(stderr, "Opening: %s\n", tmp_file);
#endif

  tmp_msg = fopen(tmp_file, "w+");
  if(bh_assert(tmp_msg == NULL)) {
    fprintf(stderr, "ERROR: Couldn't open %s file!\n", tmp_file);
    bh_exit(DEFER);
  }

  /* Qmail SENDER and RECIPIENT */
  if(sendmail == 0 && qmail_queue == 0 && pfilter == 0) {
    /* Get the Sender */
    if(getenv("SENDER") != NULL) {
      mailfrom = malloc(MAX_EMAIL_SIZE + 1);
      if(bh_assert(mailfrom == NULL)) {
        fclose(tmp_msg);
        unlink(tmp_file);
        bh_exit(DEFER);
      }
      my_strlcpy(mailfrom, (char *) getenv("SENDER"), MAX_EMAIL_SIZE + 1);
      mailfrom[MAX_EMAIL_SIZE] = (char) '\0';
      found_mailfrom = 1;
    } else {
      mailfrom = malloc(1);
      if(bh_assert(mailfrom == NULL)) {
        fclose(tmp_msg);
        unlink(tmp_file);
        bh_exit(DEFER);
      }
      mailfrom[0] = (char) '\0';
    }

    /* Get the Recipient */
    if(getenv("RECIPIENT") != NULL) {
      rcptto = malloc(MAX_EMAIL_SIZE + 1);
      if(bh_assert(rcptto == NULL)) {
        fclose(tmp_msg);
        unlink(tmp_file);
        bh_exit(DEFER);
      }
      my_strlcpy(rcptto, (char *) getenv("RECIPIENT"), MAX_EMAIL_SIZE + 1);
      rcptto[MAX_EMAIL_SIZE] = (char) '\0';
      found_rcptto = 1;
    } else {
      rcptto = malloc(1);
      if(bh_assert(rcptto == NULL)) {
        fclose(tmp_msg);
        unlink(tmp_file);
        bh_exit(DEFER);
      }
      rcptto[0] = (char) '\0';
    }
  }

  /**********************************/
  /* Read entire message from stdin */
  /**********************************/
  while(fgets(line, MAX_INPUT_LINE + 1, stdin)) {
    int lw = 0;

    /* End of Header */
    if(found_body == 0 && strncmp(line, "\n", 1) == 0) {
      if(subject == NULL) {
        strsize = 14;
        subject = (char *) malloc(strsize + 1);
        if(bh_assert(subject == NULL)) {
          fclose(tmp_msg);
          unlink(tmp_file);
          bh_exit(DEFER);
        }
        my_strlcpy(subject, "Subject: ()\n", strsize + 1);
        found_sub = 1;
        lw = fputs("Subject: ()\n\n", tmp_msg);
      } else {
        lw = fputs(line, tmp_msg);
      }
      found_body = 1;
    } else {
      lw = fputs(line, tmp_msg);
    }

    /* Max Bytes */
    if(maxsize_match == 0 && maxsize > 0 && lw > 0) {
      msg_size += my_strlen(line);
      if(msg_size > maxsize) {
        maxsize_match = 1;
        if(maxsizetrunc == 1)
          break;
      }
    } else if(maxsize_match == 0 && lw > 0)
      msg_size += my_strlen(line);

    if(found_body == 0) {
      /* Found "From " */
      if(sendmail == 1 && pfilter == 0) {
        if(found_mailfrom == 0) {
          if(!strncmp(line, "From ", 5)) {
            mailfrom = (char *) malloc(my_strlen(line) + 1);
            if(bh_assert(mailfrom == NULL)) {
              fclose(tmp_msg);
              unlink(tmp_file);
              bh_exit(DEFER);
            }
            for(j = 5, i = 0;
                line[j] != '\0' && line[j] != '\n' && line[j] != ' '; j++, i++)
              mailfrom[i] = line[j];
            mailfrom[i] = '\0';
            found_mailfrom = 1;
#if WITH_DEBUG == 1
            if(DEBUG)
              printf("Extracted Mailfrom: %s\n", mailfrom);
#endif
          }
          /* Found "        for <" */
        } else if(found_rcptto == 0) {
          if(!strncmp(line, "\tfor <", 6)) {
            rcptto = (char *) malloc(my_strlen(line) + 1);
            if(bh_assert(rcptto == NULL)) {
              fclose(tmp_msg);
              unlink(tmp_file);
              bh_exit(DEFER);
            }
            for(j = 6, i = 0;
                line[j] != '\0' && line[j] != '\n' && line[j] != '>'; j++, i++)
              rcptto[i] = line[j];
            rcptto[i] = '\0';
            found_rcptto = 1;
#if WITH_DEBUG == 1
            if(DEBUG)
              printf("Extracted Rcptto: %s\n", rcptto);
#endif
          }
        }
      }

      /* Found "Received: from " */
      if(found_ip == 0 && strncmp(line, "Received: from ", 15) == 0) {
        if(regexip(line, iprelay, hostrelay) == 0) {
          if(myrelays[0] != NULL) {
            /* Check My Relays */
            if(checkmyrelay(iprelay, myrelays) == 1) {
              found_ip = 1;
            } else
              iprelay[0] = '\0';
          } else
            found_ip = 1;
        }
        /* Found "Subject:" */
      } else if(found_sub == 0 && strncasecmp(line, "subject:", 8) == 0) {
        /* for subject line storage */
        strsize = my_strlen(line);
        subject = malloc(strsize + 1);
        if(bh_assert(subject == NULL)) {
          fclose(tmp_msg);
          unlink(tmp_file);
          bh_exit(DEFER);
        }

        /* Store Subject line */
        my_strlcpy(subject, line, strsize + 1);
        found_sub = 1;
#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, "Extracted %s", subject);
#endif
        /* Found "charset:" */
      } else if(charsets[0] != NULL && found_charset == 0 &&
                (strstr(line, "charset=") != NULL ||
                 strstr(line, "Charset=") != NULL ||
                 strstr(line, "CHARSET=") != NULL)) {

        /* for charset line storage */
        strsize = my_strlen(line);
        charset = malloc(strsize + 1);
        if(bh_assert(charset == NULL)) {
          fclose(tmp_msg);
          unlink(tmp_file);
          bh_exit(DEFER);
        }

        /* Store Charset line */
        my_strlcpy(charset, line, strsize + 1);
        found_charset = 1;
#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, "Extracted %s", charset);
#endif
      } else if(sendmail == 0 && qmail_queue == 0 &&
                strncmp(line, "Delivered-To: ", 14) == 0) {
        char *p = NULL;
        int b = 0;

        p = strchr(line, ' ');
        if(*(p + 1) != '\0')
          p++;
        rcptto = malloc(my_strlen(line) + 1);
        if(*p == '<')
          p++;
        for(b = 0; *p != '\0' && *p != '\n' && *p != '>'; p++, b++)
          rcptto[b] = *p;
        rcptto[b] = '\0';
        found_rcptto = 1;
#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, "Extracted Rcptto: %s\n", rcptto);
#endif
      }
    }
  }

#ifdef QMAIL_QFILTER
  if(bh_assert(qfilter(NULL) != 0)) {
    fclose(tmp_msg);
    unlink(tmp_file);
    bh_exit(DEFER);
  }
#endif

  /* Sender for Qmail Queue */
  if(qmail_queue == 1 &&
     getenv("QMAILUSER") != NULL && getenv("QMAILHOST") != NULL) {
    mailfrom = malloc(MAX_EMAIL_SIZE + 1);
    if(bh_assert(mailfrom == NULL)) {
      fclose(tmp_msg);
      unlink(tmp_file);
      bh_exit(DEFER);
    }
    snprintf(mailfrom, MAX_EMAIL_SIZE + 1,
             "%s@%s", (char *) getenv("QMAILUSER"),
             (char *) getenv("QMAILHOST"));
    mailfrom[MAX_EMAIL_SIZE] = (char) '\0';
    found_mailfrom = 1;
  }

  /* Recipient for Qmail Queue */
  if(qmail_queue == 1 && getenv("QMAILRCPTS") != NULL) {
    rcptto = malloc(MAX_EMAIL_SIZE + 1);
    if(bh_assert(rcptto == NULL)) {
      fclose(tmp_msg);
      unlink(tmp_file);
      bh_exit(DEFER);
    }
    my_strlcpy(rcptto, (char *) getenv("QMAILRCPTS"), MAX_EMAIL_SIZE + 1);
    rcptto[MAX_EMAIL_SIZE] = (char) '\0';
    /* Remove other Addresses */
    for(i = 0; rcptto[i] != '\0' && rcptto[i] != '\n'; i++);
    for(; rcptto[i] != '\0'; i++)
      rcptto[i] = '\0';
    found_rcptto = 1;
  }

  /* Get username and domain in qmail-queue mode */
  if((qmail_queue == 1 || pfilter == 1) &&
     rcptto != NULL && strchr(rcptto, '@') != NULL) {
    int first = 1;
    /* username */
    username = malloc(my_strlen(rcptto) + 1);
    if(bh_assert(username == NULL)) {
      fclose(tmp_msg);
      unlink(tmp_file);
      bh_exit(DEFER);
    }
    /* domain */
    sql_domain = malloc(my_strlen(rcptto) + 1);
    if(bh_assert(sql_domain == NULL)) {
      fclose(tmp_msg);
      unlink(tmp_file);
      bh_exit(DEFER);
    }

    /* Convert username and domain to Lower Case */
    for(i = 0, j = 0; rcptto[i] != '\0' && rcptto[i] != '\n'; i++) {
      if(first == 1 && rcptto[i] == '@') {
        first = 0;
        username[i] = '\0';
        continue;
      } else if(first == 1)
        username[i] = tolower(rcptto[i]);
      else {
        sql_domain[j++] = tolower(rcptto[i]);
        sql_domain[j] = '\0';
      }
    }
    if(first == 1)
      username[i] = '\0';

    /* User Config */
    strsize =
      (my_strlen(spool_dir) + my_strlen(sql_domain) + my_strlen(username) +
       18);
    config_file = malloc(strsize + 1);
    if(bh_assert(config_file == NULL)) {
      fclose(tmp_msg);
      unlink(tmp_file);
      bh_exit(DEFER);
    }
    snprintf(config_file, strsize + 1,
             "%s/conf/%s/%s/.blackhole", spool_dir, sql_domain, username);
    config_file[strsize] = (char) '\0';

    /* Domain Config */
    strsize = (my_strlen(spool_dir) + my_strlen(sql_domain) + 17);
    alt_config_file = malloc(strsize + 1);
    if(bh_assert(alt_config_file == NULL)) {
      fclose(tmp_msg);
      unlink(tmp_file);
      bh_exit(DEFER);
    }
    snprintf(alt_config_file, strsize + 1,
             "%s/conf/%s/.blackhole", spool_dir, sql_domain);

    /* Read the Configuration File for user if it exists */
    readconfig(RC_OVERWRITEOFF);

#if WITH_SQL == 1
    /* MySQL Database config for user */
    if(sqlconfig == 1) {
#if WITH_DEBUG == 1
      if(DEBUG)
        fprintf(stderr, "Using SQL, config file is %s\n", config_file);
#endif
      i = sql_config();
      if(i == 0 && DEBUG)
        fprintf(stderr,
                "%s %s %s Updated local qmail-queue config with SQL DB\n",
                timestamp, hostname, username);
    }
#endif

  }

  /**************/
  /* Virus Scan */
  /**************/
  if(virusscan > 0) {
    if(novcheck[0] != NULL && rcptto != NULL && no_check(rcptto, novcheck) == 1) {
    } else {
      /* Run Virus Scan, flush tmp file */
      fflush(tmp_msg);
      virus_ret = virus_scan();

      /* Clear out virus string if no virus found, some scan engines don't */
      if(found_virus == 0)
        virus_type = NULL;

      /* If found a virus then skip spam checks */
      if(virus_ret > 0) {
        match = MATCH_VIRUS;
        exit_mail(DENY);
      }
    }
  }

  /************************/
  /* Good Recipient Check */
  /************************/
  if(found_rcptto == 1 && rcptto != NULL) {
    for(i = 0; rcptto[i] != '\0'; i++)
      rcptto[i] = tolower(rcptto[i]);
    rcptto[i] = '\0';

#if WITH_DEBUG == 1
    if(DEBUG) {
      fprintf(stderr, "Delivered-To: %s\n", rcptto);
      fprintf(stderr, "Checking Good Recipient Addresses:\n");
    }
#endif

    /* Check */
    if(goodrcptto[0] != NULL && checkgoodemail(rcptto, goodrcptto))
      exit_mail(PERMIT);
  }

  /****************************************/
  /* Check if user disabled Spam checking */
  /****************************************/
  if(spamscan < 1) {
#if WITH_DEBUG == 1
    if(DEBUG)
      fprintf(stderr, "Spam Checking is Disabled\n");
#endif
    exit_mail(PERMIT);
  }

  /****************************/
  /* Check for non-spam users */
  /****************************/
  if(found_rcptto == 1 && rcptto != NULL) {
#if WITH_DEBUG == 1
    if(DEBUG) {
      fprintf(stderr, "Checking for NON Spam users:\n");
    }
#endif
    if(noscheck[0] != NULL && no_check(rcptto, noscheck))
      exit_mail(PERMIT);
  }

  /***************/
  /* Good Relays */
  /***************/
  if(found_ip == 1 && iprelay != NULL) {
#if WITH_DEBUG == 1
    if(DEBUG)
      fprintf(stderr, "Checking Good Relays:\n");
#endif

    /* Good Relay Check */
    if(goodrelays[0] != NULL && checkgoodrelay(iprelay, goodrelays))
      exit_mail(PERMIT);
  }

  /***********************/
  /* Good Mailfrom Check */
  /***********************/
  if(found_mailfrom == 1 && mailfrom != NULL) {
    for(i = 0; mailfrom[i] != '\0'; i++)
      mailfrom[i] = tolower(mailfrom[i]);
    mailfrom[i] = '\0';

#if WITH_DEBUG == 1
    if(DEBUG) {
      fprintf(stderr, "Mail From: %s\n", mailfrom);
      fprintf(stderr, "Checking Good Email Addresses:\n");
    }
#endif

    /* Check */
    if(goodemail[0] != NULL && checkgoodemail(mailfrom, goodemail))
      exit_mail(PERMIT);
  }

  /*******************/
  /* Check Whitelist */
  /*******************/
  if(white_list > 0)
    match = MATCH_WHITE_LIST;

  /* If maxscore is set, prepare bh_match structure */
  if(maxscore > 0) {
    bh_match = (struct bh_matches *) NULL;
    bh_match_start = bh_match;
  }

  /*******************/
  /* Run Spam checks */
  /*******************/
  /* Max Size Check */
  if(maxsize_match == 1 && maxsize > 0) {
    if(maxscore == 0 || check_match(MATCH_MXSIZE) == 1) {
#if WITH_DEBUG == 1
      fprintf(stderr, "Max Size Match found:\n");
#endif
      strsize = 20 + 25;
      log_info = malloc(strsize + 1);
      if(log_info != NULL)
        snprintf(log_info, strsize + 1,
                 "MAX BYTES(%d) Match(%d bytes)", maxsize, msg_size);
      if(maxscore == 0)
        match = MATCH_MXSIZE;
      else
        make_match(MATCH_MXSIZE);
    }
  }

#if LIBSPAMC
  /*******************************/
  /* SpamAssassin libspamc Check */
  /*******************************/
  if(spamassassin && match == NO_MATCH) {
	if(call_spamc(tmp_msg,rcptto,maxsize)) {
		/* EX_ISSPAM */
		if(maxscore == 0)
		  match = MATCH_BODY_SPAM;
		else
		  make_match(MATCH_BODY_SPAM);
	}	/* EX_NOTSPAM */
	exit_mail(PERMIT);
  }
#endif

  /* Bad Email Address Check */
  if(match == NO_MATCH && mailfrom != NULL) {
    if(maxscore == 0 || check_match(MATCH_EMAIL) == 1) {
#if WITH_DEBUG == 1
      if(DEBUG)
        fprintf(stderr, "Checking Bad Email Addresses:\n");
#endif
      if(found_mailfrom == 1 && bademail[0] != NULL &&
         checkbademail(mailfrom, bademail)) {
        if(maxscore == 0)
          match = MATCH_EMAIL;
        else
          make_match(MATCH_EMAIL);
      }
    }
  }

  /* Bad Recipient Address Check */
  if(match == NO_MATCH && rcptto != NULL) {
    if(maxscore == 0 || check_match(MATCH_RCPTTO) == 1) {
#if WITH_DEBUG == 1
      if(DEBUG)
        fprintf(stderr, "Checking Bad Recipient Addresses:\n");
#endif
      if(found_rcptto == 1 && badrcptto[0] != NULL &&
         checkbademail(rcptto, badrcptto)) {
        if(maxscore == 0)
          match = MATCH_RCPTTO;
        else
          make_match(MATCH_RCPTTO);
      }
    }
  }


  /* My Email Address Check */
  if(match == NO_MATCH && rcptto != NULL) {
    if(maxscore == 0 || check_match(MATCH_MY_EMAIL) == 1) {
#if WITH_DEBUG == 1
      if(DEBUG)
        fprintf(stderr, "Checking My Email Addresses:\n");
#endif
      /* Convert to Lower Case */
      for(i = 0; rcptto[i] != '\0'; i++)
        rcptto[i] = tolower(rcptto[i]);
      rcptto[i] = '\0';
      if(found_rcptto == 1 && myemail[0] != NULL &&
         checkmyemail(rcptto, myemail) == 0) {
        if(maxscore == 0)
          match = MATCH_MY_EMAIL;
        else
          make_match(MATCH_MY_EMAIL);
      }
    }
  }

  /* Sender DNS Check */
  if(match == NO_MATCH && check_sender > 0 && mailfrom != NULL) {
    if(maxscore == 0 || check_match(MATCH_SENDER_DNS) == 1) {
      if(check_dns(mailfrom) == 0) {
        if(maxscore == 0)
          match = MATCH_SENDER_DNS;
        else
          make_match(MATCH_SENDER_DNS);
      }
    }
  }

  /* Ignored Relays */
#if WITH_DEBUG == 1
  if(DEBUG)
    fprintf(stderr, "Checking if an Excluded Relay:\n");
#endif
  if(checkexcluded(iprelay, excludedrelays) == 1)
    excluded_ip = 1;

  if(found_ip == 1 && iprelay != NULL && excluded_ip == 0 && match == NO_MATCH) {
    /* Reverse DNS Check */
    if(match == NO_MATCH && checkreverse > 0 && hostrelay != NULL) {
      if(maxscore == 0 || check_match(MATCH_REVERSE) == 1) {
#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, "Checking Reverse DNS:\n");
#endif
        if(check_reverse(iprelay, hostrelay) == 0) {
          if(maxscore == 0)
            match = MATCH_REVERSE;
          else
            make_match(MATCH_REVERSE);
        }
      }
    }

    /* Bad Relay */
    if(match == NO_MATCH) {
      if(maxscore == 0 || check_match(MATCH_RELAY) == 1) {
#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, "Checking Bad Relay IPs:\n");
#endif
        if(badrelays[0] != NULL && checkbadrelay(iprelay, badrelays)) {
          if(maxscore == 0)
            match = MATCH_RELAY;
          else
            make_match(MATCH_RELAY);
        }
      }
    }

    /* RBL Check */
    if(match == NO_MATCH && spam_scan > 0) {
      if(maxscore == 0 || check_match(MATCH_BLACKHOLE) == 1) {
#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, "Checking RBL Lists:\n");
#endif
        if(rbllookup(iprelay, rblhosts)) {
          if(maxscore == 0)
            match = MATCH_BLACKHOLE;
          else
            make_match(MATCH_BLACKHOLE);
        }
      }
    }
  }

  /* Found "Subject:" */
  if(match == NO_MATCH && subject != NULL) {
    if(maxscore == 0 || check_match(MATCH_SUBJECT) == 1) {
#if WITH_DEBUG == 1
      if(DEBUG)
        fprintf(stderr, "Checking Subject line:\n");
#endif
      if(found_sub == 1 && badsubject[0] != NULL &&
         checkheader(subject, badsubject)) {
        if(maxscore == 0)
          match = MATCH_SUBJECT;
        else
          make_match(MATCH_SUBJECT);
      }
    }
  }

  /* Found "charset=" */
  if(match == NO_MATCH && charset != NULL) {
    if(maxscore == 0 || check_match(MATCH_CHARSET) == 1) {
#if WITH_DEBUG == 1
      if(DEBUG)
        fprintf(stderr, "Checking Charset:\n");
#endif
      if(found_charset == 1 && charset != NULL &&
         check_charset(charset, charsets) == 0) {
#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, " %s", charset);
#endif
        if(maxscore == 0)
          match = MATCH_CHARSET;
        else
          make_match(MATCH_CHARSET);
      }
    }
  }

  /**********************************/
  /* Rewind message for body checks */
  /**********************************/
  if(match == NO_MATCH) {
    if(CHAR_128 > 0 || BODY_SCAN > 0 || headers[0] != NULL ||
       badctype[0] != NULL || badencoding[0] != NULL || badattach[0] != NULL) {
#if WITH_DEBUG == 1
      if(DEBUG)
        fprintf(stderr,
                "Checking Content Type, Encoding, Headers, ASCII > 128, "
                "Attachments and Body Patterns:\n");
#endif
      rewind(tmp_msg);
      found_body = 0;
      while(fgets(line, MAX_INPUT_LINE + 1, tmp_msg)) {
        /* End of Header */
        if(found_body == 0 && strncmp(line, "\n", 1) == 0)
          found_body = 1;
        else {
          if(attach_match == 0 && badattach[0] != NULL &&
             (((strncasecmp(line, "Content-", 8) == 0) && 
              (strstr(line, "name=") != NULL)) || 
              ((strncasecmp(line, "\t", 1) == 0) &&
              (strstr(line, "name=") != NULL))
             )) 
          {
            if(maxscore == 0 || check_match(MATCH_ATTACH) == 1) {
              if(check_attach(line, badattach) == 1) {
                /* Match Content Type */
                if(maxscore == 0)
                  match = MATCH_ATTACH;
                else
                  make_match(MATCH_ATTACH);
                attach_match = 1;
              }
            }
          }
          if(ctype_match == 0 && badctype[0] != NULL &&
             strncasecmp(line, "Content-Type:", 13) == 0) {
            if(maxscore == 0 || check_match(MATCH_CTYPE) == 1) {
              if(check_ctype(line, badctype) == 1) {
                /* Match Content Type */
                if(maxscore == 0)
                  match = MATCH_CTYPE;
                else
                  make_match(MATCH_CTYPE);
                ctype_match = 1;
              }
            }
          } else if(encoding_match == 0 && badencoding[0] != NULL &&
                    strncasecmp(line, "Content-Transfer-Encoding:", 26) == 0) {
            if(maxscore == 0 || check_match(MATCH_ENC) == 1) {
              if(check_encoding(line, badencoding) == 1) {
                /* Match Content Type */
                if(maxscore == 0)
                  match = MATCH_ENC;
                else
                  make_match(MATCH_ENC);
                encoding_match = 1;
              }
            }
          }
          if(found_body == 1 &&
             ((strncasecmp(line, "Content-Type:", 13) == 0 &&
               strncasecmp(line, "Content-Type: text", 18) != 0) ||
              (strncasecmp(line, "Content-Transfer-Encoding: base64", 33)
               == 0))) {
            ascii_128_match = 1;
            body_check_match = 1;
          } else if(nosignature > 0 && found_body == 1 &&
                    strcmp(line, "--") == 0)
            body_check_match = 1;
        }

        /* Header Check */
        if(found_body == 0 && header_match == 0 && headers[0] != NULL) {
          if(maxscore == 0 || check_match(MATCH_HEADER) == 1) {
            if(checkheader(line, headers) == 1) {
              /* Match Header */
              if(maxscore == 0)
                match = MATCH_HEADER;
              else
                make_match(MATCH_HEADER);
              header_match = 1;
            }
          }
        }

        /* Ascii char check, see if they are outside latin Charsets */
        if(CHAR_128 > 0 && ascii_128_match == 0) {
          if(maxscore == 0 || check_match(MATCH_ASCII_128) == 1) {
            if(ascii_128(line) == 1) {
              if(maxscore == 0)
                match = MATCH_ASCII_128;
              else
                make_match(MATCH_ASCII_128);
              ascii_128_match = 1;
            }
          }
        }
#ifdef HAVE_LIBPCRE
        /* Body Checking, skips attachments */
        if(BODY_SCAN > 0 && found_body == 1 && body_check_match == 0) {
          if((j = check_body(line)) > 0) {
            if(maxscore == 0)
              match = j;
            else {
              if(check_match(j) == 1)
                make_match(j);
            }
            body_check_match = 1;
          }
        }
#endif
        /* Stop if Match found */
        if(match != NO_MATCH)
          break;
      }
    }
  }

  /* Only fflush once */
  if((exec_check > 0 || userazor > 0 || usepyzor > 0) && match == NO_MATCH)
    fflush(tmp_msg);

  /********************************/
  /* Run a custom program checker */
  /********************************/
  if(exec_check > 0 && match == NO_MATCH) {
    if(maxscore == 0 || check_match(MATCH_EXEC) == 1) {
      if(execute(iprelay, tmp_file, 1) == 1) {
        if(maxscore == 0)
          match = MATCH_EXEC;
        else
          make_match(MATCH_EXEC);
      }
    }
  }

  /*************************/
  /* Razor Check the Email */
  /*************************/
  if(userazor > 0 && match == NO_MATCH) {
    if(maxscore == 0 || check_match(MATCH_RAZOR) == 1) {
      if(razor_check() == 1) {
        if(maxscore == 0)
          match = MATCH_RAZOR;
        else
          make_match(MATCH_RAZOR);
      }
    }
  }

  /*************************/
  /* Pyzor Check the Email */
  /*************************/
  if(usepyzor > 0 && match == NO_MATCH) {
    if(maxscore == 0 || check_match(MATCH_PYZOR) == 1) {
      if(pyzor_check() == 1) {
        if(maxscore == 0)
          match = MATCH_PYZOR;
        else
          make_match(MATCH_PYZOR);
      }
    }
  }

  /********************************************************/
  /* Matches structure, if MAXSCORE >= 1 find right match */
  /********************************************************/
  if(maxscore > 0 && bh_match_start != NULL) {
    int count = 0;
    int delete_flag = 0, bounce_flag = 0;
    int one_box_flag = 0, exec_report_flag = 0;

    bh_match = bh_match_start;
    /* Add up scores and get actions */
    do {
#if WITH_DEBUG == 1
      if(DEBUG)
        fprintf(stderr,
                "match: %d log_info: %s\n", bh_match->match,
                bh_match->log_info);
#endif

      /* Add Score */
      score += bh_action[bh_match->match].score;

      /* Get actions if set as active */
      if(bh_action[bh_match->match].active == 1 && 
         bh_action[bh_match->match].accumulative > 0) 
      {
        /* Check Actions */
        if(bh_action[bh_match->match].delete == 1)
          delete_flag = 1;
        if(bh_action[bh_match->match].bounce == 1)
          bounce_flag = 1;
        if(bh_action[bh_match->match].one_box == 1)
          one_box_flag = 1;
        if(bh_action[bh_match->match].exec_report > 0) {
          exec_report_flag = bh_action[bh_match->match].exec_report;
        }
      }
      if(count > MAX_ACTIONS)
        break;
      count++;
    } while((bh_match = bh_match->next) != NULL);

    /* if Max score was met then setup actions and match/log_info */
    if(score >= maxscore) {
      match = bh_match_start->match;

      /* Logging */
      strsize = my_strlen(bh_match_start->log_info);
      log_info = malloc(strsize + 1);
      if(log_info != NULL)
        my_strlcpy(log_info, bh_match_start->log_info, strsize + 1);

      /* Accumulative or Just this matches actions */
      if(bh_action[bh_match_start->match].isolated > 0) {
        if(bh_action[bh_match_start->match].active == 1) {
          /* Check Actions */
          if(bh_action[bh_match_start->match].delete == 1)
            store_email = 0;
          if(bh_action[bh_match_start->match].bounce == 1)
            bouncemsg = 1;
          if(bh_action[bh_match_start->match].one_box == 1)
            allinone = 1;
          if(bh_action[bh_match_start->match].exec_report > 0)
            exec_report_flag = bh_action[bh_match_start->match].exec_report;
          else 
            exec_report_flag = 0;
        }
      } else {
        if(bh_action[bh_match_start->match].active == 1) {
          /* Check Actions */
          if(bh_action[bh_match_start->match].delete == 1)
            delete_flag = 1;
          if(bh_action[bh_match_start->match].bounce == 1)
            bounce_flag = 1;
          if(bh_action[bh_match_start->match].one_box == 1)
            one_box_flag = 1;
          if(bh_action[bh_match_start->match].exec_report > 0) {
            exec_report_flag = bh_action[bh_match_start->match].exec_report;
          }
        }
        /* Delete */
        if(delete_flag == 1)
          store_email = 0;

        /* Bounce */
        if(bounce_flag == 1)
          bouncemsg = 1;

        /* One Box */
        if(one_box_flag == 1)
          allinone = 1;
      }

      /* Exec Report */
      if(exec_report_flag > 0) {
        exec_report = exec_report_flag;
        if(bh_action[bh_match_start->match].exec_report_prog != NULL) {
          strsize = 
               my_strlen(bh_action[bh_match_start->match].exec_report_prog); 
          exec_report_prog = malloc(strsize + 1);
          my_strlcpy(exec_report_prog, 
               bh_action[bh_match_start->match].exec_report_prog, 
               strsize + 1); 
        }
        if(bh_action[bh_match_start->match].exec_report_args != NULL) {
          strsize = 
              my_strlen(bh_action[bh_match_start->match].exec_report_args); 
          exec_report_args = malloc(strsize + 1);
          my_strlcpy(exec_report_args, 
               bh_action[bh_match_start->match].exec_report_args, 
               strsize + 1); 
        }
      } else if(exec_report_flag <= 0 && exec_report == 1)
        exec_report = 0;

      if(bouncemsg == 1 && bh_action[bh_match_start->match].bounce_msg != NULL){
        strsize = my_strlen(bh_action[bh_match_start->match].bounce_msg);
        bounce_msg = malloc(strsize + 1);
        if(bounce_msg != NULL)
          my_strlcpy(bounce_msg,
                     bh_action[bh_match_start->match].bounce_msg, strsize + 1);
      }

      if(bh_action[bh_match_start->match].spam_fwd != NULL) {
        strsize = my_strlen(bh_action[bh_match_start->match].spam_fwd);
        spam_fwd = malloc(strsize + 1);
        if(spam_fwd != NULL)
          my_strlcpy(spam_fwd,
                     bh_action[bh_match_start->match].spam_fwd, strsize + 1);
      }
    }
  }

  /**************************************************************/
  /* Actions structure, setup actions for check if MAXSCORE == 0*/
  /**************************************************************/
  if(maxscore == 0 && match != NO_MATCH) {
    /* Action Check, see if an individual action is defined for this match */
    if(bh_action[match].active > 0) {
      if(bh_action[match].one_box == 1)
        allinone = 1;
      if(bh_action[match].delete == 1)
        store_email = 0;
      if(bh_action[match].bounce == 1)
        bouncemsg = 1;
      if(bh_action[match].exec_report > 0) {
        exec_report = bh_action[match].exec_report;
        if(bh_action[match].exec_report_prog != NULL) {
          strsize = 
               my_strlen(bh_action[match].exec_report_prog); 
          exec_report_prog = malloc(strsize + 1);
          my_strlcpy(exec_report_prog, 
               bh_action[match].exec_report_prog, 
               strsize + 1); 
        }
        if(bh_action[match].exec_report_args != NULL) {
          strsize = 
              my_strlen(bh_action[match].exec_report_args); 
          exec_report_args = malloc(strsize + 1);
          my_strlcpy(exec_report_args, 
               bh_action[match].exec_report_args, 
               strsize + 1); 
        }
      }
      if(bh_action[match].bounce_msg != NULL) {
        strsize = my_strlen(bh_action[match].bounce_msg);
        bounce_msg = malloc(strsize + 1);
        if(bounce_msg != NULL)
          my_strlcpy(bounce_msg, bh_action[match].bounce_msg, strsize + 1);
      }
      if(bh_action[match].spam_fwd != NULL) {
        strsize = my_strlen(bh_action[match].spam_fwd);
        spam_fwd = malloc(strsize + 1);
        if(spam_fwd != NULL)
          my_strlcpy(spam_fwd, bh_action[match].spam_fwd, strsize + 1);
      }
    }
  }

  /*********************************************/
  /* Go to Exit Mail                           */
  /*********************************************/
  exit_mail(DENY);

  /* Should never get Here */
  return 0;
}

void usage_err(int maxlevel)
{
  fprintf(stderr, "Blackhole Version-%s by ", version);
  fprintf(stderr, "Chris Kennedy (C) 2001, 2002\n\n");
  fprintf(stderr,
          "Usage: %s [config] [level] [-d [log]][-h][-li][-L][-c][-b][-t]\n",
          progname);
  fprintf(stderr, "\t\t[-S][-C][-V][-A][-B{SRPC}][-m maildir][-D][-Q][-E]\n");
  fprintf(stderr, "\t\t[-lo [type] [-SQ [host]] [-s spooldir][-O][-HA max]\n");
  fprintf(stderr, "\t\t[-W][-Res][-Rev][-r][-nor][-nos][-Ma][-I][-N][-Pf]\n");
  fprintf(stderr, "\t\t[-VD][-se][-v][-SR][-log_o][-log_si][-log_i][-log_s]\n");
  fprintf(stderr, "\t\t[-log_r]\n\n");
  if(qmail_queue == 0) {
    fprintf(stderr,
            "\tconfig    Config file used instead of default order.\n\t");
    fprintf(stderr, "  %s,\n\t  %s\n\n", default_cfg, config_file);
  } else {
    fprintf(stderr,
            "\tconfig    Config file used instead of default order.\n\t");
    fprintf(stderr, "  Global:          %s,\n\t  Domain/User Dir: %s/conf\n\n",
            default_cfg, spool_dir);
  }
  fprintf(stderr,
          "\tlevel     Level of RBL checking to do (0-%d).\n", maxlevel);
  fprintf(stderr, "\n");
  fprintf(stderr, "\t-help     This output you see here.\n");
  fprintf(stderr, "\t-version  The current version number.\n");
  fprintf(stderr, "\t-Internal Show internal settings from compile time.\n");
  fprintf(stderr, "\t-debug [logfile] Very verbose output for testing.\n");
  fprintf(stderr, "\t-config   Show current config from .blackhole file.\n");
  fprintf(stderr, "\t-Level    Show maximum possible level and current one.\n");
  fprintf(stderr, "\t-list     List current RBL Lists in order of levels.\n");
  fprintf(stderr, "\t-bounce   bounce messages blackholed back to sender.\n");
  fprintf(stderr,
          "\t-Delete   Delete all Spam and Virus email, don't store.\n");
  fprintf(stderr, "\t-norbl    No RBL Lists, skip using them for checking.\n");
  fprintf(stderr, "\t-nosig    Stop body checking at messages signature.\n");
  fprintf(stderr,
          "\t-total    Use level for maxnumber of RBL Lists matched.\n");
#ifdef HAVE_LIBPCRE
  fprintf(stderr, "\t-BSpam    Check body for known Spam patterns.\n");
  fprintf(stderr, "\t-BRacist  Check body for known Racist patterns.\n");
  fprintf(stderr, "\t-BPorn    Check body for known Porn/Sex patterns.\n");
  fprintf(stderr, "\t-BCustom  Check body for [my_body] custom patterns.\n");
#endif
  fprintf(stderr, "\t-Virus    Check for viruses, using a virus scanner.\n");
  fprintf(stderr, "\t-VDelete  Don't keep virus email, instead of clean.\n");
  fprintf(stderr, "\t-Alert    Send an alert back to the virus sender.\n");
  fprintf(stderr, "\t-Clean    Remove viruses from email, disinfect.\n");
  fprintf(stderr, "\t-maildir {dir} Change Maildir (default is Maildir).\n");
  fprintf(stderr,
          "\t-Queue    Use with qmail-qfilter to run in Qmail queue.\n");
  fprintf(stderr, "\t-Sendmail Use with Sendmail, postfix/exim/sendmail.\n");
  fprintf(stderr, "\t-spool {dir} mbox ('-s Mail' gets ~/Mail/%s).\n",
          spam_mail_box);
  fprintf(stderr, "\t-Resolve  Check that senders return address is valid.\n");
  fprintf(stderr,
          "\t-Reverse  Check reverse vs forward DNS match for relay.\n");
  fprintf(stderr, "\t-SReverse Strict Reverse DNS Checking, helo etc.\n");
  fprintf(stderr,
          "\t-Whitelist Only allow good email/relay, deny all other.\n");
#if WITH_SQL == 1
  fprintf(stderr, "\t-SQL [host] Config in Database, localhost default.\n");
#endif
  fprintf(stderr, "\t-Onebox   Change Subject: sends to the main mail box\n");
  fprintf(stderr, "\t\t\tinstead of %s or %s, works on all servers.\n",
          spam_mail_dir, virus_mail_dir);
  fprintf(stderr, "\t-HAscii {max} ASCII characters above 128, max allowed.\n");
  fprintf(stderr, "\t-Expire [days] Days to delete %s and %s mail.\n",
          spam_mail_dir, virus_mail_dir);
  fprintf(stderr, "\t-razor    Use Razor to check, must get Razor first.\n");
  fprintf(stderr, "\t-pyzor    Use Pyzor to check, must get Pyzor first.\n");
  fprintf(stderr, "\t-Maxscore Use scores for each check to choose action.\n");
  fprintf(stderr, "\t-Nameserver [ip] DNS Server for RBL Lookups to use.\n");
  fprintf(stderr, "\t-Pfilter {sender} {recipient} Postfix Content Filter.\n");
  fprintf(stderr, "\t-setup    Config/Settings cmdline Interface/Menu.\n");
  fprintf(stderr,
          "\t-log [type] Print out logging info when actions happen.\n");
  fprintf(stderr, "\t-log_ok        Log successful deliveries.\n");
  fprintf(stderr, "\t-log_score     Log Score too.\n");
  fprintf(stderr, "\t-log_size      Log Size too.\n");
  fprintf(stderr, "\t-log_iprelay   Log IpRelay too.\n");
  fprintf(stderr, "\t-log_sender    Log Sender too.\n");
  fprintf(stderr, "\t-log_recipient Log Recipient too.\n");
  fprintf(stderr, "\nVirus scanner used:\n");
#if VIRUS_SCANNER == SOPHOSSDK
  fprintf(stderr, "\tSophosSDK\n");
#elif VIRUS_SCANNER == TRENDMICRO
  fprintf(stderr, "\tTrendMicro\n");
#elif VIRUS_SCANNER == MCAFEE
  fprintf(stderr, "\tmcafee\n");
#elif VIRUS_SCANNER == CLAMSCAN
  fprintf(stderr, "\tclamscan\n");
#endif
  fprintf(stderr, "\nLogging types:\n\tsyslog");
#if WITH_SQL == 1
  fprintf(stderr, "\tsql\n");
#endif
  fprintf(stderr, "\tstderr\tstdout\n\n");
}

void internal_settings(void)
{
  printf("\nVERSION=\"%s\"\n", version);
  printf("\nQMAIL_QUEUE=\"%d\"\n", QMAIL_QUEUE);
  printf("QMAIL_QFILTER=\"%d\"\n", qmail_qfilter);
  printf("MAIL_DIR=\"%s\"\n", MAIL_DIR);
  printf("SPAM_MAIL_DIR=\"%s\"\n", SPAM_MAIL_DIR);
  printf("VIRUS_MAIL_DIR=\"%s\"\n", VIRUS_MAIL_DIR);
  printf("SPAM_MAIL_BOX=\"%s\"\n", SPAM_MAIL_BOX);
  printf("VIRUS_MAIL_BOX=\"%s\"\n", VIRUS_MAIL_BOX);
  printf("SENDMAIL=\"%d\"\n", SENDMAIL);
  printf("COURIER=\"%d\"\n", COURIER);
  printf("USE_MAILDIR=\"%d\"\n", USE_MAILDIR);
  printf("SM_SPOOL_DIR=\"%s\"\n", SM_SPOOL_DIR);
  printf("SM_LOCAL_SPOOL=\"%s\"\n", SM_LOCAL_SPOOL);
  printf("LOCKFILE=\"%s\"\n", LOCKFILE);
  printf("SETGID_SENDMAIL=\"%d\"\n", SETGID_SENDMAIL);
  printf("BH_CONFIG=\"%s\"\n", BH_CONFIG);
  printf("QUEUE_CONFIG=\"%s\"\n", QUEUE_CONFIG);
  printf("SQL_CONFIG=\"%d\"\n", SQL_CONFIG);
  printf("SQL_USER=\"%s\"\n", SQL_USER);
  printf("SQL_PASS=\"%s\"\n", SQL_PASS);
  printf("SQL_SERVER=\"%s\"\n", SQL_SERVER);
  printf("SQL_DOMAIN=\"%s\"\n", SQL_DOMAIN);
  printf("EXPIRE_TIME=\"%d\"\n", EXPIRE_TIME);
  printf("MAXOPTION=\"%d\"\n", MAXOPTION);
  printf("PRIORITY=\"%d\"\n", PRIORITY);
  printf("RAZOR_BIN=\"%s\"\n", RAZOR_BIN);
  printf("PYZOR_BIN=\"%s\"\n", PYZOR_BIN);
  printf("MCAFEE_DAT_DIR=\"%s\"\n", MCAFEE_DAT_DIR);
  printf("MCAFEE_UVSCAN=\"%s\"\n", MCAFEE_UVSCAN);
  printf("USE_LOG=\"%d\"\n", USE_LOG);
  printf("LOG_TYPE=\"%d\"\n", LOG_TYPE);
  printf("ALLINONE=\"%d\"\n", ALLINONE);
  printf("STORE_EMAIL=\"%d\"\n", STORE_EMAIL);
  printf("VIRUS_SCAN=\"%d\"\n", VIRUS_SCAN);
  printf("VIRUS_ALERT=\"%d\"\n", VIRUS_ALERT);
  printf("DISINFECT=\"%d\"\n", DISINFECT);
  printf("SPAM_SCAN=\"%d\"\n", SPAM_SCAN);
  printf("BOUNCE_MSG=\"%d\"\n", BOUNCE_MSG);
  printf("CHECK_SENDER=\"%d\"\n", CHECK_SENDER);
  printf("WHITE_LIST=\"%d\"\n", WHITE_LIST);
  printf("CHECK_REVERSE=\"%d\"\n", CHECK_REVERSE);
  printf("CHECK_HELO=\"%d\"\n", CHECK_HELO);
  printf("CUSTOM_BODY_THRESHHOLD=\"%d\"\n", CUSTOM_BODY_THRESHHOLD);
  printf("SPAM_BODY_THRESHHOLD=\"%d\"\n", SPAM_BODY_THRESHHOLD);
  printf("PORN_BODY_THRESHHOLD=\"%d\"\n", PORN_BODY_THRESHHOLD);
  printf("RACIST_BODY_THRESHHOLD=\"%d\"\n", RACIST_BODY_THRESHHOLD);
  printf("NO_BODY_CHECK_SIGNATURE=\"%d\"\n", NO_BODY_CHECK_SIGNATURE);
  printf("BH_SPOOL_DIR=\"%s\"\n", BH_SPOOL_DIR);
#ifdef WITH_SQL
  printf("WITH_SQL=\"%d\"\n", WITH_SQL);
#endif
#ifndef WITH_SQL
  printf("WITH_SQL=\"0\"\n");
#endif
#ifdef WITH_PQSQL
  printf("WITH_PQSQL=\"%d\"\n", WITH_PQSQL);
#endif
#ifndef WITH_PQSQL
  printf("WITH_PQSQL=\"0\"\n");
#endif
#ifdef WITH_MYSQL
  printf("WITH_MYSQL=\"%d\"\n", WITH_MYSQL);
#endif
#ifndef WITH_MYSQL
  printf("WITH_MYSQL=\"0\"\n");
#endif
#ifdef WITH_DEBUG
  printf("WITH_DEBUG=\"%d\"\n", WITH_DEBUG);
#endif
#ifndef WITH_DEBUG
  printf("WITH_DEBUG=\"0\"\n");
#endif
#ifdef PROGEXEC
  printf("EXEC_PROG=\"%d\"\n", exec_report);
  printf("PROGEXEC=\"%s\"\n", PROGEXEC);
#endif
  printf("EXEC_CHECK_RET=\"%d\"\n", EXEC_CHECK_RET);
  printf("EXEC_CHECK_PROG=\"%s\"\n", EXEC_CHECK_PROG);
  printf("VIRUS_SCANNER=\"%d\"\n", VIRUS_SCANNER);
  if(VIRUS_SCANNER == CLAMSCAN)
    printf("CLAMSCAN_BIN=\"%s\"\n", CLAMSCAN_BIN);
#if SOPHOS_RIPMIME == 1
  printf("SOPHOS_RIPMIME=\"%d\"\n", SOPHOS_RIPMIME);
#endif
  if(dns_srv != NULL)
    printf("DNS_SRV=\"%s\"\n", dns_srv);
#ifdef HAVE_LIBPCRE
  printf("HAVE_LIBPCRE=\"%d\"\n", HAVE_LIBPCRE);
#endif
}

void make_match(int check)
{
  struct bh_matches *pcur, *ptmp;

  /* Mark start if first in list, else increment to next in line */
  if(bh_match_start == NULL) {
    bh_match = (struct bh_matches *) malloc(sizeof(struct bh_matches));
    bh_match_start = bh_match;

    /* Fill Match Structure */
    bh_match->match = check;
    strsize = my_strlen(log_info);
    bh_match->log_info = (char *) malloc(strsize + 1);
    if(bh_match->log_info != NULL)
      my_strlcpy(bh_match->log_info, log_info, strsize + 1);

    /* Mark this as the last in the list */
    bh_match->next = (struct bh_matches *) NULL;
  } else {
#if WITH_DEBUG == 1
    if(DEBUG) {
      fprintf(stderr,
              "comparing bh_action[%d].score = %f with bh_action[%d].score = %f\n",
              check, bh_action[check].score, bh_match->match,
              bh_action[bh_match->match].score);
    }
#endif
    if(bh_action[check].score <= bh_action[bh_match->match].score) {
      bh_match->next = (struct bh_matches *) malloc(sizeof(struct bh_matches));
      bh_match = bh_match->next;

      /* Fill Match Structure */
      bh_match->match = check;
      strsize = my_strlen(log_info);
      bh_match->log_info = malloc(strsize + 1);
      if(bh_match->log_info != NULL)
        my_strlcpy(bh_match->log_info, log_info, strsize + 1);

      /* Mark this as the last in the list */
      bh_match->next = (struct bh_matches *) NULL;
    } else {
      ptmp = (struct bh_matches *) malloc(sizeof(struct bh_matches));
      if(bh_action[bh_match_start->match].score < bh_action[check].score) {
        ptmp->match = check;
        strsize = my_strlen(log_info);
        ptmp->log_info = (char *) malloc(strsize + 1);
        if(ptmp->log_info != NULL)
          my_strlcpy(ptmp->log_info, log_info, strsize + 1);
        ptmp->next = bh_match_start;
        bh_match = ptmp;
        bh_match_start = ptmp;
      } else {
        pcur = (struct bh_matches *) malloc(sizeof(struct bh_matches));
        pcur = bh_match_start;
        do {
          if(bh_action[pcur->next->match].score < bh_action[pcur->match].score){
            ptmp->next = pcur->next;
            pcur = pcur->next;
            break;
          }
          ptmp = pcur;
          pcur = pcur->next;
        } while(pcur->next != NULL);
      }
    }
  }
}

int check_match(int check)
{
  /* See if we should enter this check, mainly checking passthru setting */
  if((bh_action[check].passthru == 0 && bh_match_start != NULL) ||
     bh_match_start == NULL)
    return 1;

  /* Not going to do it */
  return 0;
}

int time_stamp(char *timestamp)
{
  time_t current;
  struct tm *t = localtime(&current);
  int year;

  extern char *tzname[2];

  char *weekdays[] = { "Sun", "Mon", "Tue", "Wed", "Thur", "Fri", "Sat" };
  char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
    "Sep", "Oct", "Nov", "Dec"
  };

  current = time(NULL);
  localtime(&current);

  year = t->tm_year + 1900;

  //strsize = 3 + 3 + (typlen(int) * 5) + my_strlen(tzname[t->tm_isdst]) + 7;

  snprintf(timestamp, 64 + 1,
           "%s %s %2d %02d:%02d:%02d %s %d",
           weekdays[t->tm_wday], months[t->tm_mon],
           t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
           tzname[t->tm_isdst], year);
  timestamp[64] = (char) '\0';

  return 0;
}

int readconfig(int SHOW_CONFIG)
{
  FILE *config;
  int i = 0, j = 0;
  int line_cnt = 0, opt_cnt = 0;
  enum sections where = 0;
  char *section = NULL, *buffer = NULL;
  char *line;
  char *config_buffer;

  /* Overwrite current config completely? */
  if(SHOW_CONFIG == RC_OVERWRITEOFF)
    ow_cfg = 1;
  else
    ow_cfg = 0;

  /* Open Config File, tries mbox/.blackhole,.blackhole,/etc/blackhole.conf */
  if(SHOW_CONFIG == RC_GLOBAL) {
    config = fopen(default_cfg, "r");
    if(config == NULL) {
      fprintf(stderr, "ERROR Reading Global Config %s\n", default_cfg);
      return 1;
    }
  } else {
    /* Check if wanting relative or full path to config */
    if(config_file[0] != '/') {
      strsize = (my_strlen(config_file) + my_strlen(homedir) + 1);
      config_buffer = malloc(strsize + 1);
      if(config_buffer == NULL)
        return 1;
      snprintf(config_buffer, strsize + 1, "%s/%s", homedir, config_file);
      config = fopen(config_buffer, "r");

      /* Copy to config_file variable if successful */
      if(config != NULL) {
        strsize = my_strlen(config_buffer);
        config_file = malloc(strsize + 1);
        if(config_file == NULL)
          return 1;
        my_strlcpy(config_file, config_buffer, strsize + 1);
      }
      free(config_buffer);
    } else
      config = fopen(config_file, "r");

    /* If still not found, try the alternative */
    if(config == NULL) {
      if(alt_config_file[0] != '/') {
        strsize = my_strlen(alt_config_file) + my_strlen(homedir) + 1;
        config_buffer = malloc(strsize + 1);
        if(config_buffer == NULL)
          return 1;
        snprintf(config_buffer, strsize + 1, "%s/%s", homedir, alt_config_file);
        config = fopen(config_buffer, "r");

        /* Copy to config_file variable if successful */
        if(config != NULL) {
          strsize = my_strlen(config_buffer);
          config_file = malloc(strsize + 1);
          if(config_file == NULL)
            return 1;
          my_strlcpy(config_file, config_buffer, strsize + 1);
        }
        free(config_buffer);
      } else {
        config = fopen(alt_config_file, "r");

        if(config != NULL) {
          strsize = my_strlen(alt_config_file);
          config_file = malloc(strsize + 1);
          if(config_file == NULL)
            return 1;
          my_strlcpy(config_file, alt_config_file, strsize + 1);
        }
      }
    }
  }

  /* No Config, Exit */
  if(config == NULL)
    return 0;

#if WITH_DEBUG == 2
  fprintf(stderr, "Using User(%d) ** Config File ** %s\n", 
       SHOW_CONFIG, config_file);
#endif

  section = (char *) malloc(MAX_CONFIG_LINE + 1);
  if(section == NULL)
    return (1);

  line = (char *) malloc(MAX_CONFIG_LINE + 1);
  if(line == NULL)
    return (1);

  buffer = (char *) malloc(MAX_CONFIG_LINE + 1);
  if(buffer == NULL)
    return (1);

  i = 0;
  while((fgets(line, MAX_CONFIG_LINE + 1, config)) != NULL) {
    /* Get Section */
    if(strncmp(line, "[", 1) == 0) {
      line_cnt++;
      count = 0;
      opt_cnt = 0;
      for(i = 0, j = 1;
          j <= MAX_CONFIG_LINE && line[j] != ']' && line[j] != '\0'; i++, j++)
        section[i] = line[j];
      if(line[j] != ']')
        continue;
      section[i] = '\0';

      /* Which Section? */
      if((where = get_section(section)) == 0) {
        fprintf(stderr, "\n%s: Illegal Section %s!\n", config_file, section);
      }

      if(SHOW_CONFIG == RC_SHOW && section[0] != '\0') {
        printf("[%s]\n", section);
        if((line_cnt % 23) == 0) {
          fprintf(stderr, " -- More --");
          while(fgetc(stdin) != '\n');
        }
      }
      continue;
      /* Skip Comment */
    } else if(strncmp(line, "#", 1) == 0) {
      continue;
      /* Skip Empty Line */
    } else if(strncmp(line, "\n", 1) == 0) {
      continue;
      /* Not a section */
    } else if(where == 0) {
      continue;
      /* copy into buffer */
    } else {
      line_cnt++;
      opt_cnt++;
      if(opt_cnt > (maxoptions - 1))
        continue;
      for(i = 0; line[i] != '\0' && line[i] != '\n'; i++)
        buffer[i] = line[i];
      buffer[i] = '\0';
      count++;
    }

    /* Print Config */
    if(SHOW_CONFIG == RC_SHOW && buffer[0] != '\0') {
      printf("%s\n", buffer);
      if((line_cnt % 23) == 0) {
        fprintf(stderr, " -- More --");
        while(fgetc(stdin) != '\n');
      }
      continue;
    }

    /* fill associative arrays */
    if(buffer[0] != '\0') {
      if(add_option(where, buffer) == 1)
        return 1;
      else if(cfg_int == 1) {
        add_cur_option(where, buffer, opt_cnt); 
      }
    }
  }
  fclose(config);
  if(SHOW_CONFIG == RC_SHOW)
    printf("\n");

  if(section != NULL)
    free(section);
  if(buffer != NULL)
    free(buffer);
  if(line != NULL)
    free(line);

  return 0;
}

int get_section(char *section)
{
  enum sections where = 0;

  /* get which section */
  if(!strcmp(section, "my_relay"))
    where = MY_RELAY;
  else if(!strcmp(section, "good_relay"))
    where = GOOD_RELAY;
  else if(!strcmp(section, "bad_relay"))
    where = BAD_RELAY;
  else if(!strcmp(section, "good_email"))
    where = GOOD_EMAIL;
  else if(!strcmp(section, "bad_email"))
    where = BAD_EMAIL;
  else if(!strcmp(section, "bad_subject"))
    where = BAD_SUB;
  else if(!strcmp(section, "rbl_hosts"))
    where = RBL_HOSTS;
  else if(!strcmp(section, "nosignature"))
    where = NOSIG;
  else if(!strcmp(section, "level"))
    where = CONFLEVEL;
  else if(!strcmp(section, "maxscore"))
    where = MAXSCORE;
  else if(!strcmp(section, "bounce"))
    where = BOUNCE_550;
  else if(!strcmp(section, "smtp_bounce"))
    where = SMTP_BOUNCE_550;
  else if(!strcmp(section, "bounce_msg"))
    where = BOUNCE_MES;
  else if(!strcmp(section, "virus_bounce_msg"))
    where = VBOUNCE_MES;
  else if(!strcmp(section, "rbl_check"))
    where = RBL_CHK;
  else if(!strcmp(section, "sscan"))
    where = SPAM_CHK;
  else if(!strcmp(section, "vscan"))
    where = VIRUS_CHK;
  else if(!strcmp(section, "valert"))
    where = VIRUS_MSG;
  else if(!strcmp(section, "vclean"))
    where = VIRUS_CL;
  else if(!strcmp(section, "vdelete"))
    where = VDEL;
  else if(!strcmp(section, "delete") || !strcmp(section, "sdelete"))
    where = DEL;
  else if(!strcmp(section, "body_check_spam"))
    where = BODY_CHK_S;
  else if(!strcmp(section, "body_check_porn"))
    where = BODY_CHK_P;
  else if(!strcmp(section, "body_check_racist"))
    where = BODY_CHK_R;
  else if(!strcmp(section, "white_list"))
    where = WHITE_LIST_CHK;
  else if(!strcmp(section, "my_email"))
    where = MY_EMAIL;
  else if(!strcmp(section, "check_dns"))
    where = DNS_CHK;
  else if(!strcmp(section, "one_box"))
    where = ALLONE;
  else if(!strcmp(section, "body_check"))
    where = BODY_CHK;
  else if(!strcmp(section, "my_body"))
    where = MY_BODY_CHK;
  else if(!strcmp(section, "charsets"))
    where = CHARSETS;
  else if(!strcmp(section, "ascii_128"))
    where = MAX_ASCII_128;
  else if(!strcmp(section, "expire"))
    where = EXPIRE;
  else if(!strcmp(section, "check_reverse"))
    where = REVERSE;
  else if(!strcmp(section, "strict_reverse"))
    where = HELO;
  else if(!strcmp(section, "exec_check"))
    where = EXEC;
  else if(!strcmp(section, "razor"))
    where = RAZOR;
  else if(!strcmp(section, "pyzor"))
    where = PYZOR;
  else if(!strcmp(section, "bad_headers"))
    where = HEADER;
  else if(!strcmp(section, "excluded_relay"))
    where = EXCLUDE_RELAY;
  else if(!strcmp(section, "no_spam_check"))
    where = NOSCHK;
  else if(!strcmp(section, "no_virus_check"))
    where = NOVCHK;
  else if(!strcmp(section, "bad_ctype"))
    where = CTYPE;
  else if(!strcmp(section, "bad_encoding"))
    where = ENC;
  else if(!strcmp(section, "smtp_relay"))
    where = RFWD;
  else if(!strcmp(section, "spam_fwd"))
    where = SFWD;
  else if(!strcmp(section, "virus_fwd"))
    where = VFWD;
  else if(!strcmp(section, "ok_fwd"))
    where = OFWD;
  else if(!strcmp(section, "maxbytes"))
    where = MXSIZE;
  else if(!strcmp(section, "maxbytes_trunc"))
    where = MXSIZETRUNC;
  else if(!strcmp(section, "footer"))
    where = FOOTER;
  else if(!strcmp(section, "footer_msg"))
    where = FOOTER_MES;
  else if(!strcmp(section, "good_rcptto"))
    where = GOOD_RCPTTO;
  else if(!strcmp(section, "bad_rcptto"))
    where = BAD_RCPTTO;
  else if(!strcmp(section, "virus_header"))
    where = VIRUS_HEADER;
  else if(!strcmp(section, "spam_header"))
    where = SPAM_HEADER;
  else if(!strcmp(section, "virus_bcc_to"))
    where = BFWD;
  else if(!strcmp(section, "sreport"))
    where = SREPORT;
  else if(!strcmp(section, "bad_attachment"))
    where = BAD_ATTACH;
  else if(!strcmp(section, "debug"))
    where = CONF_DEBUG;
  else if(!strcmp(section, "bad_subject_action"))
    where = A_MATCH_SUBJECT;
  else if(!strcmp(section, "bad_email_action"))
    where = A_MATCH_EMAIL;
  else if(!strcmp(section, "bad_relay_action"))
    where = A_MATCH_RELAY;
  else if(!strcmp(section, "rbl_check_action"))
    where = A_MATCH_BLACKHOLE;
  else if(!strcmp(section, "body_check_spam_action"))
    where = A_MATCH_BODY_SPAM;
  else if(!strcmp(section, "body_check_porn_action"))
    where = A_MATCH_BODY_PORN;
  else if(!strcmp(section, "body_check_racist_action"))
    where = A_MATCH_BODY_RACIST;
  else if(!strcmp(section, "white_list_action"))
    where = A_MATCH_WHITE_LIST;
  else if(!strcmp(section, "my_email_action"))
    where = A_MATCH_MY_EMAIL;
  else if(!strcmp(section, "check_dns_action"))
    where = A_MATCH_SENDER_DNS;
  else if(!strcmp(section, "body_check_action"))
    where = A_MATCH_MY_BODY;
  else if(!strcmp(section, "charsets_action"))
    where = A_MATCH_CHARSET;
  else if(!strcmp(section, "ascii_128_action"))
    where = A_MATCH_ASCII_128;
  else if(!strcmp(section, "check_reverse_action"))
    where = A_MATCH_REVERSE;
  else if(!strcmp(section, "exec_action"))
    where = A_MATCH_EXEC;
  else if(!strcmp(section, "razor_action"))
    where = A_MATCH_RAZOR;
  else if(!strcmp(section, "pyzor_action"))
    where = A_MATCH_PYZOR;
  else if(!strcmp(section, "bad_headers_action"))
    where = A_MATCH_HEADER;
  else if(!strcmp(section, "bad_ctype_action"))
    where = A_MATCH_CTYPE;
  else if(!strcmp(section, "bad_encoding_action"))
    where = A_MATCH_ENC;
  else if(!strcmp(section, "bad_maxbytes_action"))
    where = A_MATCH_MXSIZE;
  else if(!strcmp(section, "bad_rcptto_action"))
    where = A_MATCH_RCPTTO;
  else if(!strcmp(section, "bad_attachment_action"))
    where = A_MATCH_ATTACH;
#ifdef LIBSPAMC
  else if(!strcmp(section, "spamassassin"))
    where = SPAM_ASSASSIN_CHK;
#endif
  else {
    where = 0;
  }

  /* Return Section */
  return where;
}

int add_cur_option(int where_cur, char *buffer, int opt_cnt)
{
  int i;
  
  /* Search for right section */
  for(i=0;cfg[i].id != 0 && cfg[i].id != where_cur;i++);

  if(cfg[i].id == where_cur && my_strlen(buffer) > 0) {
    if(opt_cnt <= 1) {
      strsize = ((MAX_CONFIG_LINE * MAXOPTION) + MAXOPTION);
      cfg[i].cur.strval = malloc(strsize + 1); 
      if(cfg[i].cur.strval == NULL)
        exit(1);
      strcpy(cfg[i].cur.strval,"");
      strncat(cfg[i].cur.strval, buffer, my_strlen(buffer) + 1);
      strcat(cfg[i].cur.strval, "\n");
    } else if(opt_cnt > 1 && cfg[i].cur.strval != NULL) {
      strncat(cfg[i].cur.strval, buffer, my_strlen(buffer) + 1);
      strcat(cfg[i].cur.strval, "\n");
    }
  }
  return 0;
}

int add_to_array(char *item, char *array[], int pos) {
  /* Overwrite? */
  if(ow_cfg == RC_OVERWRITEOFF)
    if(array[pos] != NULL)
      while(array[pos++] != NULL);

  if(item == NULL)
    return pos+1;

  /* Read from include file, or just put into array */
  if((strncmp(item, "/", 1) == 0) && get_file_size(item) != 0) {
#if WITH_INCLUDE_FILE == 1
    FILE *fd;
    char *iline;

    iline = malloc(MAX_CONFIG_LINE + 1);
    if(bh_assert(iline == NULL))
      return pos+1;
    fd = fopen(item, "r");
    if(bh_assert(fd == NULL))
      return pos+1;

    while(fgets(iline, MAX_CONFIG_LINE + 1, fd)) {
      int j;

      /* Skip blank or comment lines */
      if(iline[0] == '#' || iline[0] == '\n' || my_strlen(iline) < 1)
        continue;

      /* Remove ending new line */
      for(j=0;iline[j] != '\0';j++)
        if(iline[j] == '\n')
          iline[j] = '\0';

      /* Insert into config array */
      strsize = my_strlen(iline);
      array[pos] = (char *) malloc(strsize + 1);  
      if(array[pos] == NULL)
        return pos+1;
      my_strlcpy(array[pos], iline, strsize + 1);

      pos++;
    }
    
    fclose(fd); 
#else
    if(DEBUG)
      fprintf(stderr, "ERROR: not compiled with include file support!\n");
#endif
  } else {
    strsize = my_strlen(item);
    array[pos] = (char *) malloc(strsize + 1);
    if(array[pos] == NULL)
      return pos+1;
    my_strlcpy(array[pos], item, strsize + 1);
  }

  /* Return new position */
  return pos+1; 
}

int add_option(int where_cur, char *buffer)
{
  enum sections where = where_cur;
  int j;

  if(buffer[0] == '#' || buffer[0] == '\n' || my_strlen(buffer) < 1)
    return 0;
  
  for(j=0;buffer[j] != '\0';j++)
    if(buffer[j] == '\n')
      buffer[j] = '\0';

  switch (where) {
  case MY_RELAY:
    count = add_to_array(buffer, myrelays, count-1);
    break;
  case MY_EMAIL:
    count = add_to_array(buffer, myemail, count-1);
    break;
  case GOOD_EMAIL:
    count = add_to_array(buffer, goodemail, count-1);
    break;
  case BAD_EMAIL:
    count = add_to_array(buffer, bademail, count-1);
    break;
  case GOOD_RCPTTO:
    count = add_to_array(buffer, goodrcptto, count-1);
    break;
  case BAD_RCPTTO:
    count = add_to_array(buffer, badrcptto, count-1);
    break;
  case GOOD_RELAY:
    count = add_to_array(buffer, goodrelays, count-1);
    break;
  case BAD_RELAY:
    count = add_to_array(buffer, badrelays, count-1);
    break;
  case EXCLUDE_RELAY:
    count = add_to_array(buffer, excludedrelays, count-1);
    break;
  case BAD_SUB:
    count = add_to_array(NULL, badsubject, count-1);
    strsize = my_strlen(buffer) + 9;
    badsubject[count - 1] = (char *) malloc(strsize + 1);
    snprintf(badsubject[count - 1], strsize + 1, "Subject: %s", buffer);
    break;
  case HEADER:
    count = add_to_array(buffer, headers, count-1);
    break;
  case RBL_HOSTS:
    count = add_to_array(buffer, rblhosts, count-1);
    rblhosts[count] = NULL;
    break;
  case MY_BODY_CHK:
    count = add_to_array(buffer, mybody, count-1);
    break;
  case CHARSETS:
    count = add_to_array(buffer, charsets, count-1);
    break;
  case NOSCHK:
    count = add_to_array(buffer, noscheck, count-1);
    break;
  case NOVCHK:
    count = add_to_array(buffer, novcheck, count-1);
    break;
  case CTYPE:
    count = add_to_array(buffer, badctype, count-1);
    break;
  case ENC:
    count = add_to_array(buffer, badencoding, count-1);
    break;
  case BAD_ATTACH:
    count = add_to_array(buffer, badattach, count-1);
    break;
  case FOOTER_MES:
    strsize = my_strlen(buffer);
    footer_msg = (char *) malloc(strsize + 1);
    my_strlcpy(footer_msg, buffer, strsize + 1);
    break;
  case BOUNCE_MES:
    strsize = my_strlen(buffer);
    bounce_msg = (char *) malloc(strsize + 1);
    my_strlcpy(bounce_msg, buffer, strsize + 1);
    break;
  case VBOUNCE_MES:
    strsize = my_strlen(buffer);
    virus_bounce_msg = (char *) malloc(strsize + 1);
    my_strlcpy(virus_bounce_msg, buffer, strsize + 1);
    break;
  case RFWD:
    strsize = my_strlen(buffer);
    relay_fwd = (char *) malloc(strsize + 1);
    my_strlcpy(relay_fwd, buffer, strsize + 1);
    break;
  case SFWD:
    strsize = my_strlen(buffer);
    spam_fwd = (char *) malloc(strsize + 1);
    my_strlcpy(spam_fwd, buffer, strsize + 1);
    break;
  case VFWD:
    strsize = my_strlen(buffer);
    virus_fwd = (char *) malloc(strsize + 1);
    my_strlcpy(virus_fwd, buffer, strsize + 1);
    break;
  case OFWD:
    strsize = my_strlen(buffer);
    mail_fwd = (char *) malloc(strsize + 1);
    my_strlcpy(mail_fwd, buffer, strsize + 1);
    break;
  case BFWD:
    strsize = my_strlen(buffer);
    bcc_fwd = (char *) malloc(strsize + 1);
    my_strlcpy(bcc_fwd, buffer, strsize + 1);
    break;
  case EXEC:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      exec_check = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      exec_check = 1;
    else
      exec_check = 0;

    break;
  case SREPORT:
    if(buffer[0] == '-')
      exec_report = 0;
    else {
      for(j = 0; buffer[j] != '\0' && buffer[j] != '\n' &&
          buffer[j] != ' '; j++) {
        if(isdigit(buffer[j]) == 0) {
          /* Not a number */
          fprintf(stderr, "Error, bad option for exec_report! %s\n", buffer);
          exec_report = 0;
          break;
        }
      }
      exec_report = (int) atoi(buffer);
    }
    break;
  case RBL_CHK:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      spam_scan = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      spam_scan = 1;
    else
      spam_scan = 0;

    break;
  case SPAM_CHK:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      spamscan = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      spamscan = 1;
    else
      spamscan = 0;

    break;
  case BODY_CHK:
    if(buffer[0] == '-')
      MY_BODY = 0;
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      MY_BODY = 1;
    else {
      for(j = 0; buffer[j] != '\0' && buffer[j] != '\n' &&
          buffer[j] != ' '; j++) {
        if(isdigit(buffer[j]) == 0) {
          /* Not a number */
          fprintf(stderr, "Error, bad option for custom body! %s\n", buffer);
          level = 0;
          break;
        }
      }
      MY_BODY = (int) atoi(buffer);
    }
    if(MY_BODY > 0)
      BODY_SCAN = 1;
    break;
  case BODY_CHK_S:
    if(buffer[0] == '-')
      SPAM_BODY = 0;
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      SPAM_BODY = 1;
    else {
      for(j = 0; buffer[j] != '\0' && buffer[j] != '\n' &&
          buffer[j] != ' '; j++) {
        if(isdigit(buffer[j]) == 0) {
          /* Not a number */
          fprintf(stderr, "Error, bad option for spam body! %s\n", buffer);
          level = 0;
          break;
        }
      }
      SPAM_BODY = (int) atoi(buffer);
    }
    if(SPAM_BODY > 0)
      BODY_SCAN = 1;
    break;
  case BODY_CHK_P:
    if(buffer[0] == '-')
      PORN_BODY = 0;
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      PORN_BODY = 1;
    else {
      for(j = 0; buffer[j] != '\0' && buffer[j] != '\n' &&
          buffer[j] != ' '; j++) {
        if(isdigit(buffer[j]) == 0) {
          /* Not a number */
          fprintf(stderr, "Error, bad option for porn body! %s\n", buffer);
          level = 0;
          break;
        }
      }
      PORN_BODY = (int) atoi(buffer);
    }
    if(PORN_BODY > 0)
      BODY_SCAN = 1;
    break;
  case BODY_CHK_R:
    if(buffer[0] == '-')
      RACIST_BODY = 0;
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      RACIST_BODY = 1;
    else {
      for(j = 0; buffer[j] != '\0' && buffer[j] != '\n' &&
          buffer[j] != ' '; j++) {
        if(isdigit(buffer[j]) == 0) {
          /* Not a number */
          fprintf(stderr, "Error, bad option for racist body! %s\n", buffer);
          level = 0;
          break;
        }
      }
      RACIST_BODY = (int) atoi(buffer);
    }
    if(RACIST_BODY > 0)
      BODY_SCAN = 1;
    break;
  case CONF_DEBUG:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1') {
      DEBUG = (int) atoi(buffer);
      if(DEBUG < 0)
        DEBUG = 0;
    } else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      DEBUG = 1;
    else
      DEBUG = 0;
    break;
  case VIRUS_CHK:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      virusscan = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      virusscan = 1;
    else
      virusscan = 0;
    break;
  case VIRUS_MSG:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      virus_alert = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      virus_alert = 1;
    else
      virus_alert = 0;
    break;
  case VIRUS_CL:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      disinfect = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      disinfect = 1;
    else
      disinfect = 0;
    break;
  case VDEL:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      virus_delete = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      virus_delete = 1;
    else
      virus_delete = 0;
    break;
  case DEL:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      spam_delete = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      spam_delete = 1;
    else
      spam_delete = 0;
    break;
  case NOSIG:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      nosignature = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      nosignature = 1;
    else
      nosignature = 0;
    break;
  case BOUNCE_550:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      bouncemsg = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      bouncemsg = 1;
    else
      bouncemsg = 0;
    break;
  case SMTP_BOUNCE_550:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      smtp_bouncemsg = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      smtp_bouncemsg = 1;
    else
      smtp_bouncemsg = 0;
    break;
  case RAZOR:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      userazor = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      userazor = 1;
    else
      userazor = 0;
    break;
  case PYZOR:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      usepyzor = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      usepyzor = 1;
    else
      usepyzor = 0;
    break;
  case CONFLEVEL:
    if(buffer[0] == '-')
      level = 0;
    else {
      for(j = 0; buffer[j] != '\0' && buffer[j] != '\n' &&
          buffer[j] != ' '; j++) {
        if(isdigit(buffer[j]) == 0) {
          /* Not a number */
          fprintf(stderr, "Error, bad option for level! %s\n", buffer);
          level = 0;
          break;
        }
      }
      level = (int) atoi(buffer);
    }
    break;
  case MAXSCORE:
    if(buffer[0] == '-')
      maxscore = 0;
    else {
      for(j = 0; buffer[j] != '\0' && buffer[j] != '\n' &&
          buffer[j] != ' '; j++) {
        if(isdigit(buffer[j]) == 0) {
          /* Not a number */
          fprintf(stderr, "Error, bad option for maxscore! %s\n", buffer);
          maxscore = 0;
          break;
        }
      }
      maxscore = (int) atoi(buffer);
    }
    break;
  case MAX_ASCII_128:
    if(buffer[0] == '-')
      max_ascii_score = 0;
    else {
      for(j = 0; buffer[j] != '\0' && buffer[j] != '\n' &&
          buffer[j] != ' '; j++) {
        if(isdigit(buffer[j]) == 0) {
          /* Not a number */
          fprintf(stderr, "Error, bad option for max ascii 128! %s\n", buffer);
          max_ascii_score = 0;
          break;
        }
      }
      max_ascii_score = (int) atoi(buffer);
    }
    if(max_ascii_score > 0)
      CHAR_128 = 1;
    break;
  case MXSIZE:
    if(buffer[0] == '-')
      maxsize = 0;
    else {
      for(j = 0; buffer[j] != '\0' && buffer[j] != '\n' &&
          buffer[j] != ' '; j++) {
        if(isdigit(buffer[j]) == 0) {
          /* Not a number */
          fprintf(stderr, "Error, bad option for maxsize! %s\n", buffer);
          level = 0;
          break;
        }
      }
      maxsize = (int) atoi(buffer);
    }
    break;
  case MXSIZETRUNC:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      maxsizetrunc = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      maxsizetrunc = 1;
    else
      maxsizetrunc = 0;
    break;
  case WHITE_LIST_CHK:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      white_list = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      white_list = 1;
    else
      white_list = 0;
    break;
  case DNS_CHK:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      check_sender = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      check_sender = 1;
    else
      check_sender = 0;
    break;
  case REVERSE:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      checkreverse = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      checkreverse = 1;
    else
      checkreverse = 0;
    break;
  case FOOTER:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      footer = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      footer = 1;
    else
      footer = 0;
    break;
  case HELO:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      checkhelo = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      checkhelo = 1;
    else
      checkhelo = 0;
    if(checkhelo > 0)
      checkreverse = 1;
    break;
  case ALLONE:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      allinone = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      allinone = 1;
    else
      allinone = 0;
    break;
  case EXPIRE:
    if(buffer[0] == '-')
      expire_time = 0;
    else {
      for(j = 0; buffer[j] != '\0' && buffer[j] != '\n' &&
          buffer[j] != ' '; j++) {
        if(isdigit(buffer[j]) == 0) {
          /* Not a number */
          fprintf(stderr, "Error, bad option for max expire! %s\n", buffer);
          level = 0;
          break;
        }
      }
      expire_time = (int) atoi(buffer);
    }
    break;
  case SPAM_HEADER:
    get_action(where, buffer);
    break;
  case VIRUS_HEADER:
    get_action(where, buffer);
    break;
  case A_MATCH_SUBJECT:
    get_action(where, buffer);
    break;
  case A_MATCH_EMAIL:
    get_action(where, buffer);
    break;
  case A_MATCH_RELAY:
    get_action(where, buffer);
    break;
  case A_MATCH_BLACKHOLE:
    get_action(where, buffer);
    break;
  case A_MATCH_BODY_SPAM:
    get_action(where, buffer);
    break;
  case A_MATCH_BODY_PORN:
    get_action(where, buffer);
    break;
  case A_MATCH_BODY_RACIST:
    get_action(where, buffer);
    break;
  case A_MATCH_WHITE_LIST:
    get_action(where, buffer);
    break;
  case A_MATCH_MY_EMAIL:
    get_action(where, buffer);
    break;
  case A_MATCH_SENDER_DNS:
    get_action(where, buffer);
    break;
  case A_MATCH_MY_BODY:
    get_action(where, buffer);
    break;
  case A_MATCH_CHARSET:
    get_action(where, buffer);
    break;
  case A_MATCH_ASCII_128:
    get_action(where, buffer);
    break;
  case A_MATCH_REVERSE:
    get_action(where, buffer);
    break;
  case A_MATCH_EXEC:
    get_action(where, buffer);
    break;
  case A_MATCH_RAZOR:
    get_action(where, buffer);
    break;
  case A_MATCH_PYZOR:
    get_action(where, buffer);
    break;
  case A_MATCH_HEADER:
    get_action(where, buffer);
    break;
  case A_MATCH_CTYPE:
    get_action(where, buffer);
    break;
  case A_MATCH_ENC:
    get_action(where, buffer);
    break;
  case A_MATCH_RCPTTO:
    get_action(where, buffer);
    break;
  case A_MATCH_ATTACH:
    get_action(where, buffer);
    break;
#ifdef LIBSPAMC
  case SPAM_ASSASSIN_CHK:
    if(buffer[0] == '0' || buffer[0] == '-' || buffer[0] == '1')
      spamassassin = (int) atoi(buffer);
    else if((strncmp(buffer, "on", 2) == 0)
            || (strncmp(buffer, "true", 4) == 0))
      spamassassin = 1;
    else
      spamassassin = 0;

    break;
#endif
  default:
    fprintf(stderr, "%s: Error, No such section #%d!\n", config_file, where);
    return 1;
  }
  return 0;
}

int get_action(int check_id, char *buffer)
{
  char *name, *value;
  int i = 0, j = 0;

  name = malloc(my_strlen(buffer) + 1);
  if(name == NULL)
    return 1;
  value = malloc(my_strlen(buffer) + 1);
  if(value == NULL)
    return 1;

  /* Get name and value pair */
  while(j <= MAX_CONFIG_LINE &&
        buffer[i] != '\0' && buffer[i] != ' ' && buffer[i] != '=') {
    name[j++] = buffer[i];
    i++;
  }
  name[j] = '\0';
  while(j <= MAX_CONFIG_LINE &&
        buffer[i] != '\0' && (buffer[i] == ' ' || buffer[i] == '='))
    i++;
  j = 0;
  while(buffer[i] != '\0') {
    value[j++] = buffer[i];
    i++;
  }
  value[j] = '\0';

  /* Check what name is being setup */
  if(strcmp(name, "active") == 0) {
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      bh_action[check_id].active = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      bh_action[check_id].active = 1;
    else
      bh_action[check_id].active = 0;
  } else if(strcmp(name, "one_box") == 0) {
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      bh_action[check_id].one_box = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      bh_action[check_id].one_box = 1;
    else
      bh_action[check_id].one_box = 0;
  } else if(strcmp(name, "delete") == 0) {
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      bh_action[check_id].delete = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      bh_action[check_id].delete = 1;
    else
      bh_action[check_id].delete = 0;
  } else if(strcmp(name, "bounce_msg") == 0) {
    strsize = my_strlen(value);
    bh_action[check_id].bounce_msg = malloc(strsize + 1);
    my_strlcpy(bh_action[check_id].bounce_msg, value, strsize + 1);
  } else if(strcmp(name, "bounce") == 0) {
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      bh_action[check_id].bounce = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      bh_action[check_id].bounce = 1;
    else
      bh_action[check_id].bounce = 0;
  } else if(strcmp(name, "spam_fwd") == 0) {
    strsize = my_strlen(value);
    bh_action[check_id].spam_fwd = malloc(strsize + 1);
    my_strlcpy(bh_action[check_id].spam_fwd, value, strsize + 1);
  } else if(strcmp(name, "score") == 0) {
    bh_action[check_id].score = (float) atof(value);
  } else if(strcmp(name, "exec_report") == 0) {
    bh_action[check_id].exec_report = (float) atof(value);
  } else if(strcmp(name, "accumulative") == 0) {
    bh_action[check_id].accumulative = (float) atof(value);
  } else if(strcmp(name, "isolated") == 0) {
    bh_action[check_id].isolated = (float) atof(value);
  } else if(WITH_EXEC_REPORT_ACTION && strcmp(name, "exec_report_prog") == 0) {
    strsize = my_strlen(value);
    bh_action[check_id].exec_report_prog = malloc(strsize + 1);
    my_strlcpy(bh_action[check_id].exec_report_prog, value, strsize + 1);
  } else if(WITH_EXEC_REPORT_ACTION && strcmp(name, "exec_report_args") == 0) {
    strsize = my_strlen(value);
    bh_action[check_id].exec_report_args = malloc(strsize + 1);
    my_strlcpy(bh_action[check_id].exec_report_args, value, strsize + 1);
  } else if(strcmp(name, "passthru") == 0) {
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      bh_action[check_id].passthru = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      bh_action[check_id].passthru = 1;
    else
      bh_action[check_id].passthru = 0;
  } else if(strcmp(name, "subject_tag") == 0) {
    int input = 1;
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      input = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      input = 1;
    else
      input = 0;
    if(check_id == SPAM_HEADER)
      spam_header.subject_tag = input;
    else if(check_id == VIRUS_HEADER)
      virus_header.subject_tag = input;
  } else if(strcmp(name, "subject_msg") == 0) {
    strsize = my_strlen(value);
    if(check_id == SPAM_HEADER) {
      spam_header.subject_msg = malloc(strsize + 1);
      my_strlcpy(spam_header.subject_msg, value, strsize + 1);
    } else {
      virus_header.subject_msg = malloc(strsize + 1);
      my_strlcpy(virus_header.subject_msg, value, strsize + 1);
    }
  } else if(strcmp(name, "subject_info") == 0) {
    int input = 1;
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      input = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      input = 1;
    else
      input = 0;
      spam_header.subject_info = input;
  } else if(strcmp(name, "subject_score") == 0) {
    int input = 1;
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      input = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      input = 1;
    else
      input = 0;
      spam_header.subject_score = input;
  } else if(strcmp(name, "subject_type") == 0) {
    int input = 1;
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      input = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      input = 1;
    else
      input = 0;
      virus_header.subject_type = input;
  } else if(strcmp(name, "subject_clean") == 0) {
    int input = 1;
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      input = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      input = 1;
    else
      input = 0;
      virus_header.subject_clean = input;
  } else if(strcmp(name, "version") == 0) {
    int input = 1;
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      input = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      input = 1;
    else
      input = 0;
    if(check_id == SPAM_HEADER)
      spam_header.version = input;
    else if(check_id == VIRUS_HEADER)
      virus_header.version = input;
  } else if(strcmp(name, "sender") == 0) {
    int input = 1;
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      input = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      input = 1;
    else
      input = 0;
    if(check_id == SPAM_HEADER)
      spam_header.sender = input;
    else if(check_id == VIRUS_HEADER)
      virus_header.sender = input;
  } else if(strcmp(name, "relay") == 0) {
    int input = 1;
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      input = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      input = 1;
    else
      input = 0;
    if(check_id == SPAM_HEADER)
      spam_header.relay = input;
    else if(check_id == VIRUS_HEADER)
      virus_header.relay = input;
  } else if(strcmp(name, "match") == 0) {
    int input = 1;
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      input = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      input = 1;
    else
      input = 0;
    if(check_id == SPAM_HEADER)
      spam_header.match = input;
    else if(check_id == VIRUS_HEADER)
      virus_header.match = input;
  } else if(strcmp(name, "type") == 0) {
    int input = 1;
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      input = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      input = 1;
    else
      input = 0;
    if(check_id == SPAM_HEADER)
      spam_header.type = input;
    else if(check_id == VIRUS_HEADER)
      virus_header.type = input;
  } else if(strcmp(name, "status") == 0) {
    int input = 1;
    if(value[0] == '0' || value[0] == '-' || value[0] == '1')
      input = (int) atoi(value);
    else if((strncmp(value, "on", 2) == 0) || (strncmp(value, "true", 4) == 0))
      input = 1;
    else
      input = 0;
    if(check_id == SPAM_HEADER)
      spam_header.status = input;
    else if(check_id == VIRUS_HEADER)
      virus_header.status = input;
  }

  free(name);
  free(value);
  return 0;
}

void exit_mail(int action)
{
  extern int errno;
  char *mbox = NULL;
  char *mail_dir = NULL;
  char *mail_box = NULL;
  char *fwd = NULL;

  /* Set Max Score */
  if(maxscore == 0 && match != NO_MATCH)
    score = 1.00;

  /* Setup variables if Spam or a Virus */
  if(found_virus == 1) {
    /** Added by: Joe Stump <joe@joestump.ent **/
    // I added this here to make sure that send_mail_box() was invoked
    // since that is where the STDOUT is invoked from. Since writing to
    // STDOUT and an mbox is basically the same procedure it made
    // the most sense to put it there.
    if(use_maildir == 0 && (sendmail == 1 || send_to_stdout == 1) && pfilter ==
 0) {
      /* Mailbox */
      strsize = my_strlen(virus_mail_box);
      mail_box = malloc(strsize + 1);
      if(bh_assert(mail_box == NULL)) {
        unlink(tmp_file);
        bh_exit(DEFER);
      }
      my_strlcpy(mail_box, virus_mail_box, strsize + 1);
    } else {
      /* Maildir */
      strsize = my_strlen(virus_mail_dir);
      mail_dir = malloc(strsize + 1);
      if(bh_assert(mail_dir == NULL)) {
        unlink(tmp_file);
        bh_exit(DEFER);
      }
      my_strlcpy(mail_dir, virus_mail_dir, strsize + 1);
    }
    /* Forward */
    if(virus_fwd != NULL) {
      strsize = my_strlen(virus_fwd);
      fwd = malloc(strsize + 1);
      if(bh_assert(fwd == NULL)) {
        unlink(tmp_file);
        bh_exit(DEFER);
      }
      my_strlcpy(fwd, virus_fwd, strsize + 1);
    }
    /* Delete */
    if(virus_delete > 0)
      store_email = 0;
  } else if(match != NO_MATCH) {
    if(use_maildir == 0 && sendmail == 1 && pfilter == 0) {
      /* Mailbox */
      strsize = my_strlen(spam_mail_box);
      mail_box = malloc(strsize + 1);
      if(bh_assert(mail_box == NULL)) {
        unlink(tmp_file);
        bh_exit(DEFER);
      }
      my_strlcpy(mail_box, spam_mail_box, strsize + 1);
    } else {
      /* Maildir */
      strsize = my_strlen(spam_mail_dir);
      mail_dir = malloc(strsize + 1);
      if(bh_assert(mail_dir == NULL)) {
        unlink(tmp_file);
        bh_exit(DEFER);
      }
      my_strlcpy(mail_dir, spam_mail_dir, strsize + 1);
    }
    /* Forward */
    if(spam_fwd != NULL) {
      strsize = my_strlen(spam_fwd);
      fwd = malloc(strsize + 1);
      if(bh_assert(fwd == NULL)) {
        unlink(tmp_file);
        bh_exit(DEFER);
      }
      my_strlcpy(fwd, spam_fwd, strsize + 1);
    }
    /* Delete */
    if(spam_delete > 0)
      store_email = 0;
  }

  /********************************************/
  /* Setup Mail Dir for storing blocked email */
  /********************************************/
  /* sendmail with mailbox */
  if(pfilter == 1) {
    if(store_email > 0) {
      /* Postfix Filter */
      strsize =
        my_strlen(fname) + my_strlen(spool_dir) + my_strlen(mail_dir) + 10;
      spam_file = malloc(strsize + 1);
      if(bh_assert(spam_file == NULL)) {
        unlink(tmp_file);
        bh_exit(DEFER);
      }
      snprintf(spam_file, strsize + 1,
               "%s/msg/%s/new/%s", spool_dir, mail_dir, fname);
    }
  } else if(use_maildir == 0 && sendmail == 1) {
    /* [sendmail] different mailbox */
    if(allinone < 1 && match != NO_MATCH) {
      /* [spooldir] local spool directory specified */
      if(SPOOLDIR > 0 && spooldir != NULL && my_strlen(spooldir) > 0) {
        strsize =
          my_strlen(homedir) + my_strlen(spooldir) + my_strlen(mail_box) + 2;
        spam_file = malloc(strsize + 1);
        if(bh_assert(spam_file == NULL)) {
          unlink(tmp_file);
          bh_exit(DEFER);
        }
        snprintf(spam_file, strsize + 1,
                 "%s/%s/%s", homedir, spooldir, mail_box);
        /* [spam_mail_box] no local spool, base of home directory */
      } else {
        strsize = my_strlen(homedir) + my_strlen(mail_box) + 1;
        spam_file = malloc(strsize + 1);
        if(bh_assert(spam_file == NULL)) {
          unlink(tmp_file);
          bh_exit(DEFER);
        }
        snprintf(spam_file, strsize + 1, "%s/%s", homedir, mail_box);
      }
    }
    /* [sendmail] Full path given */
    if(sendmail_dir[0] == '/') {
      strsize = my_strlen(username) + my_strlen(sendmail_dir) + 1;
      mbox = malloc(strsize + 1);
      if(bh_assert(mbox == NULL)) {
        unlink(tmp_file);
        bh_exit(DEFER);
      }
      snprintf(mbox, strsize + 1, "%s/%s", sendmail_dir, username);
      /* relative path */
    } else {
      int i;
      for(i = 0; sendmail_dir[i] != '\0'; i++);
      /* trailing slash */
      if(sendmail_dir[i] == '/') {
        strsize = my_strlen(homedir) + my_strlen(sendmail_dir) + 7;
        mbox = malloc(strsize + 1);
        if(bh_assert(mbox == NULL)) {
          unlink(tmp_file);
          bh_exit(DEFER);
        }
        snprintf(mbox, strsize + 1, "%s/%s/Inbox", homedir, sendmail_dir);
        /* full filename */
      } else {
        strsize = my_strlen(homedir) + my_strlen(sendmail_dir) + 1;
        mbox = malloc(strsize + 1);
        if(bh_assert(mbox == NULL)) {
          unlink(tmp_file);
          bh_exit(DEFER);
        }
        snprintf(mbox, strsize + 1, "%s/%s", homedir, sendmail_dir);
      }
    }
  } else {
    /* Qmail Queue file paths */
    if(qmail_queue == 1) {
      if(match != NO_MATCH) {
        if(allinone > 0) {
          strsize = my_strlen(spool_dir) + my_strlen(fname) + 9;
          final_msg = malloc(strsize + 1);
          if(bh_assert(final_msg == NULL)) {
            unlink(tmp_file);
            bh_exit(DEFER);
          }
          snprintf(final_msg, strsize + 1, "%s/msg/new/%s", spool_dir, fname);
        } else {
          strsize =
            my_strlen(spool_dir) + my_strlen(fname) + my_strlen(mail_dir) + 10;
          spam_file = malloc(strsize + 1);
          if(bh_assert(spam_file == NULL)) {
            unlink(tmp_file);
            bh_exit(DEFER);
          }
          snprintf(spam_file, strsize + 1,
                   "%s/msg/%s/new/%s", spool_dir, mail_dir, fname);
        }
      } else {
        strsize = my_strlen(spool_dir) + my_strlen(fname) + 9;
        final_msg = malloc(strsize + 1);
        if(bh_assert(final_msg == NULL)) {
          unlink(tmp_file);
          bh_exit(DEFER);
        }
        snprintf(final_msg, strsize + 1, "%s/msg/new/%s", spool_dir, fname);
      }
      /* [maildir] Qmail or Maildir full path */
    } else if(strncmp(maildir, "/", 1) == 0) {
      /* different maildir */
      if(allinone < 1 && match != NO_MATCH) {
        strsize =
          my_strlen(fname) + my_strlen(maildir) + my_strlen(mail_dir) + 6;
        spam_file = malloc(strsize + 1);
        if(bh_assert(spam_file == NULL)) {
          unlink(tmp_file);
          bh_exit(DEFER);
        }
        snprintf(spam_file, strsize + 1,
                 "%s/%s/new/%s", maildir, mail_dir, fname);
        /* same maildir */
      } else if(allinone > 0) {
        strsize = my_strlen(fname) + my_strlen(maildir) + 5;
        final_msg = malloc(strsize + 1);
        if(bh_assert(final_msg == NULL)) {
          unlink(tmp_file);
          bh_exit(DEFER);
        }
        snprintf(final_msg, strsize + 1, "%s/new/%s", maildir, fname);
      }
      /* [maildir] Qmail or Maildir relative path */
    } else {
      /* different maildir */
      if(allinone < 1 && match != NO_MATCH) {
        strsize =
          my_strlen(homedir) + my_strlen(fname) + my_strlen(maildir) +
          my_strlen(mail_dir) + 7;
        spam_file = malloc(strsize + 1);
        if(bh_assert(spam_file == NULL)) {
          unlink(tmp_file);
          bh_exit(DEFER);
        }
        snprintf(spam_file, strsize + 1,
                 "%s/%s/%s/new/%s", homedir, maildir, mail_dir, fname);
        /* same maildir */
      } else {
        strsize =
          my_strlen(homedir) + my_strlen(fname) + my_strlen(maildir) + 6;
        final_msg = malloc(strsize + 1);
        if(bh_assert(final_msg == NULL)) {
          unlink(tmp_file);
          bh_exit(DEFER);
        }
        snprintf(final_msg, strsize + 1,
                 "%s/%s/new/%s", homedir, maildir, fname);
      }
    }
  }

  /* Expire Maildir format mailboxes */
  if(sendmail == 0 && expire_time > 0) {
    expire(spam_mail_dir, "cur", expire_time);
    expire(spam_mail_dir, "new", expire_time);
    if(virusscan > 0) {
      expire(virus_mail_dir, "cur", expire_time);
      expire(virus_mail_dir, "new", expire_time);
    }
  }

  if(match != NO_MATCH || found_virus == 1) {
    /* Close TMP file */
    fclose(tmp_msg);

    /* BCC Admin Email */
    if(found_virus == 1 && bcc_fwd != NULL) {
#if WITH_DEBUG == 1
      if(DEBUG)
        fprintf(stderr,
                "    Sending administrator <%s> virus alert email!\n", bcc_fwd);
#endif
      if(bh_assert
         (bcc_alert(mailfrom, iprelay, relay_fwd, rcptto, bcc_fwd) != 0));
    } 

    /* Manually bounce message with smtp */
    if(smtp_bouncemsg > 0 && (bouncemsg > 0 || virus_alert > 0)) {
      if(found_virus == 0) {
        if(bouncemsg > 0) {
          if(bh_assert(
             smtp_bounce(mailfrom, rcptto, relay_fwd, bounce_msg) != 0))
               fprintf(stderr, "ERROR: smtp_bounce failed for Spam.\n");
          else {
            bouncemsg = 0;
            if(DEBUG) {
              fprintf(stderr, "\nSMTP BOUNCED back to sender.\n");
              if(bounce_msg != NULL)
                fprintf(stderr, "Bounce Message: %s\n", bounce_msg);
            }
          }
        }
      } else if(virus_alert > 0) {
        char *vbm;

        strsize = my_strlen(virus_bounce_msg) + my_strlen(virus_type) + 50;
        vbm = malloc(strsize + 1); 
        if(vbm == NULL)
          bh_exit(DEFER);

        snprintf(vbm, strsize + 1, 
            "%s\r\nVirus Name: %s\r\nUser Rejected Message (#5.1.1)", 
            virus_bounce_msg, virus_type);

        if(bh_assert(
           smtp_bounce(mailfrom, rcptto, relay_fwd, vbm) != 0))
             fprintf(stderr, "ERROR: smtp_bounce failed for Virus.\n");
        else {
          virus_alert = 0;
          if(DEBUG) {
            fprintf(stderr, "\nBOUNCED back to sender.\n");
            if(virus_bounce_msg != NULL)
              fprintf(stderr, "Virus Bounce Message: %s\n", virus_bounce_msg);
          }
        }
      }
    }

    /**********************/
    /* Message is BLOCKED */
    /**********************/
    if(pfilter == 1) {
      if(store_email > 0) {
        int ret = 0;

        /* Postfix Filter */
        if(bh_assert
           (maildir_put
            (spam_file, tmp_file, mailfrom, iprelay, relay_fwd, fwd) != 0)) {
          unlink(tmp_file);
          bh_exit(DEFER);
        }
        if(bh_assert((ret = pfilter_put(spam_file)) != 0)) {
          unlink(tmp_file);
          bh_exit(ret);
        }
        unlink(spam_file);
      }
    } else if(store_email > 0) {
      /** Added by: Joe Stump <joe@joestump.net> **/
      if(use_maildir == 0 && sendmail == 1) {
        if(fwd != NULL) {
          if(bh_assert(maildir_put(final_msg, tmp_file, mailfrom, iprelay,
                                   relay_fwd, fwd) != 0)) {
            unlink(tmp_file);
            bh_exit(DEFER);
          }
        } else if(allinone > 0) {
          if(bh_assert(send_mail_box(mbox, tmp_file, mailfrom, iprelay) != 0)) {
            unlink(tmp_file);
            bh_exit(DEFER);
          }
        } else {
          if(bh_assert
             (send_mail_box(spam_file, tmp_file, mailfrom, iprelay) != 0)) {
            unlink(tmp_file);
            bh_exit(DEFER);
          }
        }
      } else {
        if(allinone > 0) {
          if(bh_assert(maildir_put(final_msg, tmp_file, mailfrom, iprelay,
                                   relay_fwd, fwd) != 0)) {
            unlink(tmp_file);
            bh_exit(DEFER);
          }
        } else {
          if(bh_assert(maildir_put(spam_file, tmp_file, mailfrom, iprelay,
                                   relay_fwd, fwd) != 0)) {
            unlink(tmp_file);
            bh_exit(DEFER);
          }
        }
      }
    }

    /* Execute a program, could report spam to RBLs or someone else */
    if((found_virus == 0) && (exec_report > 0)) {
#if WITH_DEBUG == 1
      if(DEBUG)
        fprintf(stderr, "Maxscore: %d Score: %f Exec_Score: %d\n", 
	     maxscore, score, exec_report);
#endif
      if(score >= exec_report)
        execute(iprelay, tmp_file, 0);
    }

    /* Remove TMP FILE */
    unlink(tmp_file);

    /* Block and Exit */
    if(found_virus == 1)
      bh_exit(BLOCK_VIRUS);
    else if(match != NO_MATCH)
      bh_exit(BLOCK_SPAM);
  } else {
    /***************************/
    /* Message is OK and CLEAN */
    /***************************/
    if(footer) 
	fprintf(tmp_msg, "\n---------------\n%s",footer_msg);

    /* Close TMP file */
    fclose(tmp_msg);

    if(pfilter == 1) {
      int ret = 0;
      /* Postfix Filter */
      if(bh_assert((ret = pfilter_put(tmp_file)) != 0)) {
        unlink(tmp_file);
        bh_exit(ret);
      }
    /** Added by: Joe Stump <joe@joestump.net> **/
    // Not sure if this needs to be here or not.
    } else if(use_maildir == 0 && (sendmail == 1 || send_to_stdout == 1) 
      && mail_fwd == NULL) {
      if(bh_assert(send_mail_box(mbox, tmp_file, mailfrom, iprelay) != 0)) {
        unlink(tmp_file);
        bh_exit(DEFER);
      }
    } else if(sendmail == 1 || allinone > 0 || qmail_queue == 1 ||
              mail_fwd != NULL) {
      if(bh_assert
         (maildir_put
          (final_msg, tmp_file, mailfrom, iprelay, relay_fwd, mail_fwd) != 0)) {
        unlink(tmp_file);
        bh_exit(DEFER);
      }
    }
    unlink(tmp_file);

    /* Pass Message Through and exit */
    bh_exit(OK);

    /* Never will get here */
    exit(0);
  }
}

void bh_exit(int status)
{
  /* Bounced Message */
#ifndef QMAIL_QFILTER
  if(qmail_queue == 0) {
#endif
    if(virus_alert > 0 && status == BLOCK_VIRUS) {
      fprintf(stdout, "%s\nVirus Name: %s\nUser Rejected Message (#5.1.1)\n", 
           virus_bounce_msg, virus_type);
    } else if(bouncemsg > 0 && status == BLOCK_SPAM)
      fprintf(stdout, "%s\n", bounce_msg);
#ifndef QMAIL_QFILTER
  }
#endif

  /* Debugging */
  if(DEBUG && (status == BLOCK_SPAM || status == BLOCK_VIRUS)) {
    fprintf(stderr, "\n\n*** BLACKHOLE DEBUG OUTPUT ***\n");
    fprintf(stderr, "[%s] ", timestamp);
    fprintf(stderr, "Message Size: (%d) bytes ", msg_size);
    if(score > 0)
      fprintf(stderr, "Score: (%.2f) ", score);
    if(bouncemsg > 0 || (virus_alert > 0 && found_virus > 0)) {
      fprintf(stderr, "\nBOUNCED back to sender.\n");
      if(found_virus > 0) {
        if(virus_bounce_msg != NULL)
          fprintf(stderr, "Virus Bounce Message: %s\n", virus_bounce_msg);
      } else {
        if(bounce_msg != NULL)
          fprintf(stderr, "Bounce Message: %s\n", bounce_msg);
      }
    } else 
      fprintf(stderr, "\n");
    if(store_email < 1)
      fprintf(stderr, "Deleted email, message not saved\n"); 
    if(iprelay != NULL && my_strlen(iprelay) > 0)
      fprintf(stderr, "IP Relay:   %s\n", iprelay);
    if(hostrelay != NULL && my_strlen(hostrelay) > 0)
      fprintf(stderr, "Host Relay: %s\n", hostrelay);
    if(mailfrom != NULL && my_strlen(mailfrom) > 0)
      fprintf(stderr, "Mailfrom:   %s\n", mailfrom);
    if(rcptto != NULL && my_strlen(rcptto) > 0)
      fprintf(stderr, "Recipient:  %s\n", rcptto);
    if(subject != NULL && my_strlen(subject) > 0)
      fprintf(stderr, "%s", subject);
    if(charset != NULL && my_strlen(charset) > 0)
      fprintf(stderr, "%s", charset);
    if(log_info != NULL && my_strlen(log_info) > 0)
      fprintf(stderr, "SpamMatch:  %s\n", log_info);
    if(matches[match] != NULL && matches[match] != NO_MATCH)
      fprintf(stderr, "SpamInfo:   %s\n", matches[match]);
    if(virusscan > 0) {
      if(found_virus != 0) {
        fprintf(stderr, "VirusType:  %s\n", virus_type);
        if(viruses[virus_ret] != NULL)
          fprintf(stderr, "VirusState: %s\n", viruses[virus_ret]);
      }
    }
    fprintf(stderr, "*** END OF DEBUG OUTPUT ***\n");
  }

  /* Logging */
  if(use_log == 1) {
    if(status == BLOCK_VIRUS) {
      if(virus_type != NULL) {
        strsize = 
             my_strlen(viruses[virus_ret]) + my_strlen(virus_type) + 7;
        log_info = malloc(strsize + 1);
        if(log_info != NULL) {
          snprintf(log_info, strsize + 1,
                 "Virus %s %s", viruses[virus_ret], virus_type);
          logging(log_info);
        }
      }
    } else if(status == BLOCK_SPAM) {
      if(log_info) {
         char *tmpbuf;
         strsize = my_strlen(matches[match]) + my_strlen(log_info) + 1;
         tmpbuf = malloc(strsize + 1);
         if(tmpbuf != NULL) {
           snprintf(tmpbuf, strsize + 1, "%s %s", matches[match], log_info);
           logging(tmpbuf);
         }
      } else
	 logging("SPAM");
    } 
    else if(status == DEFER)
      logging("DEFER");
    else if(status == OK && log_ok == 1) 
      logging("OK");
  }

  if(status == DEFER) {
    if(sendmail == 1)
      exit(EX_TEMPFAIL);
    else if(qmail_queue == 1)
      exit(53);
    else
      exit(0);
  } else if(status == BLOCK_SPAM) {
    if(sendmail == 1 && bouncemsg > 0)
      exit(EX_NOUSER);
    else if(sendmail == 1)
      exit(0);
    else if(qmail_queue == 1) {
#ifdef QMAIL_QFILTER
      int ret = 0;
 
      if(spam_fwd != NULL) {
        if(bouncemsg > 0)
          exit(31);
        else
          exit(0);
      }
#endif
      if(allinone > 0) {
#ifdef QMAIL_QFILTER
        if((ret = qfilter(final_msg)) == 0) {
          if(bouncemsg > 0)
            exit(31);
          else
#endif
            exit(0);
#ifdef QMAIL_QFILTER
        } else
          exit(ret);
#endif
      } else if(bouncemsg > 0)
        exit(31);
      else
#ifdef QMAIL_QFILTER
        exit(0);
#endif
#ifndef QMAIL_QFILTER
      exit(99);
#endif
    } else if(courier == 1 && bouncemsg > 0)
      exit(EX_NOUSER);
    else if(bouncemsg > 0)
      exit(100);
    else
      exit(99);
  } else if(status == BLOCK_VIRUS) {
    if(sendmail == 1 && virus_alert > 0)
      exit(EX_NOUSER);
    else if(sendmail == 1)
      exit(0);
    else if(qmail_queue == 1) {
#ifdef QMAIL_QFILTER
      int ret = 0;

      if(virus_fwd != NULL) {
        if(bouncemsg > 0)
          exit(31);
        else
          exit(0);
      }
#endif
      if(allinone > 0) {
#ifdef QMAIL_QFILTER
        if((ret = qfilter(final_msg)) == 0) {
          if(virus_alert > 0)
            exit(31);
          else
#endif
            exit(0);
#ifdef QMAIL_QFILTER
        } else
          exit(ret);
#endif
      } else if(virus_alert > 0)
        exit(31);
      else
#ifdef QMAIL_QFILTER
        exit(0);
#endif
#ifndef QMAIL_QFILTER
      exit(99);
#endif
    } else if(courier == 1 && virus_alert > 0)
      exit(EX_NOUSER);
    else if(virus_alert > 0)
      exit(100);
    else
      exit(99);
  } else if(status == OK) {
    /* We wrote it out, so exit silently */
    if((allinone > 0 || mail_fwd != NULL) && qmail_queue == 0 && sendmail == 0)
      exit(99);
#ifdef QMAIL_QFILTER
    else if(qmail_qfilter == 1) {
      int ret = 0;

      if(mail_fwd == NULL) {
        if((ret = qfilter(final_msg)) == 0)
          exit(0);
        else
          exit(ret);
      } else
        exit(0);
    }
#endif

    /* Permit email through */
    exit(0);
  } else {
    exit(status);
  }
}

int send_mail_box(char *mbox, char *tmpfile, char *mailfrom, char *iprelay)
{
  FILE *tmp, *mb;
  char *buffer;
  int i;
  int eoh = 0;

  buffer = malloc(MAX_INPUT_LINE + 1);
  if(buffer == NULL)
    return 1;

  tmp = fopen(tmpfile, "r");
  if(tmp == NULL)
    return 1;

  /* Lock Mailbox */
  if(mbox_lock(mbox) != 0)
    return 1;


  /** Added By: Joe Stump <joe@joestump.net **/
  // Simpley use /dev/stdout instead of mbox if they
  // have chosen to send it to SDTOUT.
  if(send_to_stdout == 1) {
    mb = fopen("/dev/stdout", "w"); 
  } else {
    mb = fopen(mbox, "a"); 
  }

  if(mb == NULL)
    return 1;

  if(match == NO_MATCH) {
    while(fgets(buffer, MAX_INPUT_LINE + 1, tmp) != '\0') {
      fputs(buffer, mb);
    }
  } else {
    while(fgets(buffer, MAX_INPUT_LINE + 1, tmp) != '\0') {
      /* Clean Attachment */
      if(eoh == 1 && disinfect > 0 && found_virus == 1 &&
         ((strncasecmp(buffer, "Content-Type:", 13) == 0 &&
         strncasecmp(buffer, "Content-Type: text", 18) != 0) ||
         strncasecmp(buffer, "Content-Transfer-Encoding: base64", 33) == 0))
        break;

      if(virus_header.subject_tag > 0 && eoh == 0 && found_virus == 1 &&
         strncasecmp(buffer, "subject:", 8) == 0) {
        /* Subject Tag */
        fprintf(mb, "Subject: ");
        if(virus_header.subject_msg != NULL && 
             my_strlen(virus_header.subject_msg) > 0)
          fprintf(mb, "%s", virus_header.subject_msg);
        if(virus_header.subject_type > 0 || virus_header.subject_clean > 0) {
          fprintf(mb, "[");
          if(virus_header.subject_type > 0)
            fprintf(mb, "%s", virus_type);
          if(virus_header.subject_type > 0 && virus_header.subject_clean > 0)
            fprintf(mb, " ");
          if(virus_header.subject_clean > 0)
            fprintf(mb, "%s", viruses[virus_ret]);
          fprintf(mb, "]");
        }

        /* output rest of subject */
        for(i = 8; i <= (MAX_INPUT_LINE - 1) &&
            buffer[i] != '\n' && buffer[i] != '\0'; i++)
          fputc(buffer[i], mb);
        fputc('\n', mb);

        continue;
      } else if(spam_header.subject_tag > 0 && eoh == 0 && match != NO_MATCH &&
                strncasecmp(buffer, "subject:", 8) == 0) {
        /* Subject Tag */
        fprintf(mb, "Subject: ");
        if(spam_header.subject_msg != NULL && 
             my_strlen(spam_header.subject_msg) > 0)
          fprintf(mb, "%s", spam_header.subject_msg);
        if(spam_header.subject_info > 0 || spam_header.subject_score > 0) {
          fprintf(mb, "[");
          if(spam_header.subject_info > 0)
            fprintf(mb, "%s", matches[match]);
          if(spam_header.subject_info > 0 && spam_header.subject_score > 0)
            fprintf(mb, " ");
          if(spam_header.subject_score > 0)
            fprintf(mb, "%.1f", score);
          fprintf(mb, "]");
        }

        /* output rest of subject */
        for(i = 8; i <= (MAX_INPUT_LINE - 1) &&
            buffer[i] != '\n' && buffer[i] != '\0'; i++)
          fputc(buffer[i], mb);
        fputc('\n', mb);

        continue;
      }

      /* Insert X-BlackHole: Headers */
      if(eoh == 0 && strncmp(buffer, "\n", 1) == 0) {
        if((found_virus == 1 && virus_header.version > 0) ||
           (match != NO_MATCH && spam_header.version > 0))
          fprintf(mb, "X-BlackHole: Version %s by Chris Kennedy (C) 2002\n",
                  version);
        if(mailfrom != NULL && ((found_virus == 1 && virus_header.sender > 0) ||
                                (match != NO_MATCH && spam_header.sender > 0)))
          fprintf(mb, "X-BlackHole-Sender: %s\n", mailfrom);
        if(iprelay != NULL && ((found_virus == 1 && virus_header.relay > 0) ||
                               (match != NO_MATCH && spam_header.relay > 0)))
          fprintf(mb, "X-BlackHole-Relay: %s\n", iprelay);
        if(matches[match] != NULL &&
           ((found_virus == 1 && virus_header.match > 0) ||
            (match != NO_MATCH && spam_header.match > 0)))
          fprintf(mb, "X-BlackHole-Match: %s\n", matches[match]);
        if(log_info != NULL && ((found_virus == 1 && virus_header.status > 0) ||
                                (match != NO_MATCH && spam_header.status > 0)))
          fprintf(mb, "X-BlackHole-Info: %s\n", log_info);
        if(virusscan > 0) {
          if(virus_ret > 0 && virus_header.status > 0)
            fprintf(mb, "X-BlackHole-Virus-Status: %s\n", viruses[virus_ret]);
          if(virus_type != NULL && virus_header.type > 0)
            fprintf(mb, "X-BlackHole-Virus-Type: %s\n", virus_type);
        }
        eoh = 1;
      }
      fputs(buffer, mb);
    }
  }
  fputc('\n', mb);
  fclose(mb);

  /* Unlock Mailbox */
  if(mbox_unlock(mbox) != 0)
    return 1;

  fclose(tmp);
  return 0;
}

int mbox_lock(char *mbox)
{
  char *maillock;
  int pid, status;

  strsize = my_strlen(mbox) + 5;
  maillock = malloc(strsize + 1);
  if(maillock == NULL)
    return 1;
  snprintf(maillock, strsize + 1, "%s.lock", mbox);

  /* Fork for Lockfile */
  pid = fork();
  if(pid == -1)
    return 0;
  if(pid == 0) {
    char *lock_args[3] = {
      lockfile,
      maillock,
      '\0'
    };

    if(setgid_sendmail == 1) {
      lock_args[1] = malloc(3 + 1);
      my_strlcpy(lock_args[1], "-ml", 3 + 1);
      lock_args[2] = '\0';
    }

    /* Run Command */
    execv(lockfile, lock_args);
    exit(127);
  }
  do {
    if(waitpid(pid, &status, 0) == -1) {
      if(errno != EINTR)
        return -1;
    } else {
      status >>= 8;
      status &= 0xFF;
      if(bh_assert(status != 0))
        return 1;
      break;
    }
  } while(1);

  free(maillock);
  return 0;
}

int mbox_unlock(char *mbox)
{
  char *maillock;
  int pid, status;

  strsize = my_strlen(mbox) + 5;
  maillock = malloc(strsize + 1);
  if(maillock == NULL)
    return 1;
  snprintf(maillock, strsize + 1, "%s.lock", mbox);

  /* If we don't have to don't run lockfile again */
  if(setgid_sendmail == 0) {
    if(unlink(maillock) != 0)
      return 1;
    else
      return 0;
  }

  /* Fork for Lockfile */
  pid = fork();
  if(pid == -1)
    return 0;
  if(pid == 0) {
    char *lock_args[] = {
      lockfile,
      "-mu",
      '\0'
    };

    /* Run Command */
    execv(lockfile, lock_args);
    exit(127);
  }
  do {
    if(waitpid(pid, &status, 0) == -1) {
      if(errno != EINTR)
        return -1;
    } else {
      status >>= 8;
      status &= 0xFF;
      if(bh_assert(status != 0)) {
        /* Last attempt to remove */
        if(unlink(maillock) != 0)
          return 1;
      }
      break;
    }
  } while(1);

  free(maillock);
  return 0;
}

int maildir_put(char *vfile, char *tfile, char *mailfrom,
                char *iprelay, char *relay, char *fwd)
{
  int sd = 0, rc = 0;
  int eoh = 0;
  int i;
  struct hostent *h;
  struct sockaddr_in srcaddr, dstaddr;
  char iobuf[1024], *netbuffer = NULL;
  char *helo, *mfrm, *rcpt;

  FILE *vf = NULL, *tf = NULL;
  char *buffer;

  buffer = malloc(MAX_INPUT_LINE + 1);
  if(buffer == NULL)
    return 1;

  if(fwd != NULL) {
    netbuffer = malloc(MAX_INPUT_LINE + 1);
    if(netbuffer == NULL)
      return 1;
  }

  tf = fopen(tfile, "r");
  if(bh_assert(tf == NULL))
    return 1;

  if(fwd != NULL) {
    /* helo */
    strsize = my_strlen(hostname) + 7;
    helo = malloc(strsize + 1);
    if(helo == NULL) {
      fclose(tf);
      return 1;
    }
    snprintf(helo, strsize + 1, "helo %s\r\n", hostname);

    /* mail from: */
    if(mailfrom != NULL) {
      strsize = my_strlen(mailfrom) + 15;
      mfrm = malloc(strsize + 1);
      if(mfrm == NULL) {
        fclose(tf);
        return 1;
      }
      snprintf(mfrm, strsize + 1, "mail from: <%s>\r\n", mailfrom);
    } else {
      strsize = 15;
      mfrm = malloc(strsize + 1);
      if(mfrm == NULL) {
        fclose(tf);
        return 1;
      }
      snprintf(mfrm, strsize + 1, "mail from: <>\r\n");
    }

    /* rcpt to: */
    strsize = my_strlen(fwd) + 13;
    rcpt = malloc(strsize + 1);
    if(rcpt == NULL) {
      fclose(tf);
      return 1;
    }
    snprintf(rcpt, strsize + 1, "rcpt to: <%s>\r\n", fwd);

    /* Setup SMTP Connection */
    h = gethostbyname(relay);
    if(bh_assert(h == NULL)) {
      fclose(tf);
      return 1;
    }
    dstaddr.sin_family = h->h_addrtype;
    memcpy((char *) &dstaddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
    dstaddr.sin_port = htons(SMTP_FWD_PORT);

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if(bh_assert(sd < 0)) {
      fclose(tf);
      return 1;
    }

    srcaddr.sin_family = AF_INET;
    srcaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    srcaddr.sin_port = htons(0);

    rc = bind(sd, (struct sockaddr *) &srcaddr, sizeof(srcaddr));
    if(bh_assert(rc < 0)) {
      fclose(tf);
      return 1;
    }

    rc = connect(sd, (struct sockaddr *) &dstaddr, sizeof(dstaddr));
    if(bh_assert(rc < 0)) {
      fclose(tf);
      return 1;
    }

    /* Read from the Socket */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof iobuf);
    strsize = my_strlen(iobuf);
    my_strlcat(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    /* get 220 or leave */
    if(bh_assert(strncmp(netbuffer, "220 ", 3) != 0)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      fclose(tf);
      return 1;
    }

    /* Write to the HELO command to the Socket */
    rc = crlf_write(sd, helo, (my_strlen(helo)));
    if(bh_assert(rc <= 0))
      return 1;
    free(helo);

    /* Read from the Socket, get 250 or leave */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof(iobuf));
    strsize = my_strlen(iobuf);
    my_strlcat(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    if(bh_assert(strstr(netbuffer, "250 ") == NULL)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      fclose(tf);
      return 1;
    }

    /* Write to the MAIL FROM command to the Socket */
    rc = crlf_write(sd, mfrm, (my_strlen(mfrm)));
    if(bh_assert(rc <= 0)) {
      close(sd);
      fclose(tf);
      return 1;
    }
    /* Read from the Socket, get 250 or leave */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof(iobuf));
    strsize = my_strlen(iobuf);
    my_strlcat(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    if(bh_assert(strstr(netbuffer, "250 ") == NULL)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      fclose(tf);
      return 1;
    }
    free(mfrm);

    /* Write to the RCPT TO command to the Socket */
    rc = crlf_write(sd, rcpt, (my_strlen(rcpt)));
    if(bh_assert(rc <= 0)) {
      close(sd);
      fclose(tf);
      return 1;
    }
    free(rcpt);
    /* Read from the Socket, get 250 or leave */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof(iobuf));
    strsize = my_strlen(iobuf);
    my_strlcat(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    if(bh_assert(strstr(netbuffer, "250 ") == NULL)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      fclose(tf);
      return 1;
    }

    /* Write DATA to the Socket */
    rc = crlf_write(sd, "data\r\n", my_strlen("data\r\n"));
    if(bh_assert(rc <= 0))
      return 1;

    /* Read from the Socket, get 354 or leave */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof(iobuf));
    strsize = my_strlen(iobuf);
    my_strlcat(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    if(bh_assert(strstr(netbuffer, "354 ") == NULL)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      fclose(tf);
      return 1;
    }
  } else {
    /* Only open for read in Qmail Queue mode */
    if(qmail_queue == 1 && qmail_qfilter == 0)
      vf = fopen(vfile, "w+");
    else
      vf = fopen(vfile, "w");
    if(bh_assert(vf == NULL))
      return 1;
  }

  while(fgets(buffer, MAX_INPUT_LINE + 1, tf) != '\0') {
    /* Clean Attachment */
    if(eoh == 1 && disinfect > 0 && found_virus == 1 &&
       ((strncasecmp(buffer, "Content-Type:", 13) == 0 &&
       strncasecmp(buffer, "Content-Type: text", 18) != 0) ||
         strncasecmp(buffer, "Content-Transfer-Encoding: base64", 33) == 0))
      break;

    if(eoh == 0 && virus_header.subject_tag > 0 && found_virus == 1 &&
       strncasecmp(buffer, "subject:", 8) == 0) {
      if(fwd != NULL) {
        strcpy(netbuffer, "");

        /* Subject Tag */
        strncat(netbuffer, "Subject: ", 9);
        if(virus_header.subject_msg != NULL && 
             my_strlen(virus_header.subject_msg) > 0)
          strncat(netbuffer, 
               virus_header.subject_msg, my_strlen(virus_header.subject_msg));
        if(virus_header.subject_type > 0 || virus_header.subject_clean > 0) {
          strncat(netbuffer, "[", 1);
          if(virus_header.subject_type > 0)
            strncat(netbuffer, virus_type, my_strlen(virus_type));
          if(virus_header.subject_type > 0 && virus_header.subject_clean > 0)
            strncat(netbuffer, " ", 1);
          if(virus_header.subject_clean > 0)
            strncat(netbuffer, 
                 viruses[virus_ret], my_strlen(viruses[virus_ret]));
          strncat(netbuffer, "]", 1);
        }
        strncat(netbuffer, "\0", 1);
         
        strsize = my_strlen(netbuffer);
        rc = write(sd, netbuffer, strsize);
        if(bh_assert(rc <= 0)) {
          close(sd);
          fclose(tf);
          return 1;
        }
      } else {
        /* Subject Tag */
        fprintf(vf, "Subject: ");
        if(virus_header.subject_msg != NULL && 
             my_strlen(virus_header.subject_msg) > 0)
          fprintf(vf, "%s", virus_header.subject_msg);
        if(virus_header.subject_type > 0 || virus_header.subject_clean > 0) {
          fprintf(vf, "[");
          if(virus_header.subject_type > 0)
            fprintf(vf, "%s", virus_type);
          if(virus_header.subject_type > 0 && virus_header.subject_clean > 0)
            fprintf(vf, " ");
          if(virus_header.subject_clean > 0)
            fprintf(vf, "%s", viruses[virus_ret]);
          fprintf(vf, "]");
        }
      }

      for(i = 8; buffer[i] != '\n' && buffer[i] != '\0'; i++) {
        if(fwd != NULL) {
          strcpy(netbuffer, "");
          snprintf(netbuffer, 1 + 1, "%c", buffer[i]);
          rc = write(sd, netbuffer, 1);
          if(bh_assert(rc <= 0)) {
            close(sd);
            fclose(tf);
            return 1;
          }
        } else
          fputc(buffer[i], vf);
      }
      if(fwd != NULL) {
        rc = write(sd, "\r\n", 2);
        if(bh_assert(rc <= 0)) {
          close(sd);
          fclose(tf);
          return 1;
        }
      } else
        fputc('\n', vf);
      continue;
    } else if(eoh == 0 && spam_header.subject_tag > 0 &&
              match != NO_MATCH && strncasecmp(buffer, "subject:", 8) == 0) {
      if(fwd != NULL) {
        strcpy(netbuffer, "");

        /* Subject Tag */
        strncat(netbuffer, "Subject: ", 9);
        if(spam_header.subject_msg != NULL && 
             my_strlen(spam_header.subject_msg) > 0)
          strncat(netbuffer, 
               spam_header.subject_msg, my_strlen(spam_header.subject_msg));
        if(spam_header.subject_info > 0 || spam_header.subject_score > 0) {
          strncat(netbuffer, "[", 1);
          if(spam_header.subject_info > 0)
            strncat(netbuffer, matches[match], my_strlen(matches[match]));
          if(spam_header.subject_info > 0 && spam_header.subject_score > 0)
            strncat(netbuffer, " ", 1);
          if(spam_header.subject_score > 0) {
            char *score_str;
            strsize = typlen(float)+2;
            score_str = malloc(strsize + 1);
            if(bh_assert(score_str == NULL))
              bh_exit(DEFER);
            snprintf(score_str, strsize + 1, "%.1f", score);
            strncat(netbuffer, score_str, my_strlen(score_str));
          }
          strncat(netbuffer, "]", 1);
        }
        strncat(netbuffer, "\0", 1);
         
        strsize = my_strlen(netbuffer);
        rc = write(sd, netbuffer, strsize);
        if(bh_assert(rc <= 0)) {
          close(sd);
          fclose(tf);
          return 1;
        }
      } else {
        /* Subject Tag */
        fprintf(vf, "Subject: ");
        if(spam_header.subject_msg != NULL && 
             my_strlen(spam_header.subject_msg) > 0)
          fprintf(vf, "%s", spam_header.subject_msg);
        if(spam_header.subject_info > 0 || spam_header.subject_score > 0) {
          fprintf(vf, "[");
          if(spam_header.subject_info > 0)
            fprintf(vf, "%s", matches[match]);
          if(spam_header.subject_info > 0 && spam_header.subject_score > 0)
            fprintf(vf, " ");
          if(spam_header.subject_score > 0)
            fprintf(vf, "%.1f", score);
          fprintf(vf, "]");
        }
      }

      for(i = 8; i < 224 && buffer[i] != '\0' && buffer[i] != '\n'; i++) {
        if(fwd != NULL) {
          strcpy(netbuffer, "");
          snprintf(netbuffer, 1 + 1, "%c", buffer[i]);
          rc = write(sd, netbuffer, 1);
          if(bh_assert(rc <= 0)) {
            close(sd);
            fclose(tf);
            return 1;
          }
        } else
          fputc(buffer[i], vf);
      }

      if(fwd != NULL) {
        rc = write(sd, "\r\n", 2);
        if(bh_assert(rc <= 0)) {
          close(sd);
          fclose(tf);
          return 1;
        }
      } else
        fputc('\n', vf);
      continue;
    }

    /* Insert X-BlackHole: Headers */
    if(eoh == 0 && strncmp(buffer, "\n", 1) == 0) {
      if(fwd != NULL) {
        /* version header */
        if((found_virus == 1 && virus_header.version > 0) ||
           (match != NO_MATCH && spam_header.version > 0)) {
          strsize = my_strlen(version) + 49;
          netbuffer[strsize] = (char) '\0';
          snprintf(netbuffer, strsize + 1,
                   "X-BlackHole: Version %s by Chris Kennedy (C) 2002\r\n",
                   version);
          rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
          if(bh_assert(rc <= 0)) {
            close(sd);
            fclose(tf);
            return 1;
          }
        }
        /* sender header */
        if(mailfrom != NULL && ((found_virus == 1 && virus_header.sender > 0) ||
                                (match != NO_MATCH
                                 && spam_header.sender > 0))) {
          strsize = my_strlen(mailfrom) + 22;
          netbuffer[strsize] = (char) '\0';
          snprintf(netbuffer, strsize + 1,
                   "X-BlackHole-Sender: %s\r\n", mailfrom);
          rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
          if(bh_assert(rc <= 0)) {
            close(sd);
            fclose(tf);
            return 1;
          }
        }
        /* iprelay header */
        if(iprelay != NULL && ((found_virus == 1 && virus_header.relay > 0) ||
                               (match != NO_MATCH && spam_header.relay > 0))) {
          strsize = my_strlen(iprelay) + 23;
          netbuffer[strsize] = (char) '\0';
          snprintf(netbuffer, strsize + 1,
                   "X-BlackHole-Relay: %s\r\n", iprelay);
          rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
          if(bh_assert(rc <= 0)) {
            close(sd);
            fclose(tf);
            return 1;
          }
        }
        /* match */
        if(matches[match] != NULL &&
           ((found_virus == 1 && virus_header.match > 0) ||
            (match != NO_MATCH && spam_header.match > 0))) {
          strsize = my_strlen(matches[match]) + 21;
          netbuffer[strsize] = (char) '\0';
          snprintf(netbuffer, strsize + 1,
                   "X-BlackHole-Match: %s\r\n", matches[match]);
          rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
          if(bh_assert(rc <= 0)) {
            close(sd);
            fclose(tf);
            return 1;
          }
        }
        /* info */
        if(log_info != NULL && ((found_virus == 1 && virus_header.status > 0) ||
                                (match != NO_MATCH
                                 && spam_header.status > 0))) {
          strsize = my_strlen(log_info) + 20;
          netbuffer[strsize] = (char) '\0';
          snprintf(netbuffer, strsize + 1,
                   "X-BlackHole-Info: %s\r\n", log_info);
          rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
          if(bh_assert(rc <= 0)) {
            close(sd);
            fclose(tf);
            return 1;
          }
        }
        if(virusscan > 0) {
          /* virus status */
          if(virus_ret > 0 && virus_header.status > 0) {
            strsize = my_strlen(viruses[virus_ret]) + 28;
            netbuffer[strsize] = (char) '\0';
            snprintf(netbuffer, strsize + 1,
                     "X-BlackHole-Virus-Status: %s\r\n", viruses[virus_ret]);
            rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
            if(bh_assert(rc <= 0)) {
              close(sd);
              fclose(tf);
              return 1;
            }
          }
          /* virus type */
          if(virus_type != NULL && virus_header.type > 0) {
            strsize = my_strlen(virus_type) + 26;
            netbuffer[strsize] = (char) '\0';
            snprintf(netbuffer, strsize + 1,
                     "X-BlackHole-Virus-Type: %s\r\n", virus_type);
            rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
            if(bh_assert(rc <= 0)) {
              close(sd);
              fclose(tf);
              return 1;
            }
          }
        }
      } else {
        if((found_virus == 1 && virus_header.version > 0) ||
           (match != NO_MATCH && spam_header.version > 0))
          fprintf(vf, "X-BlackHole: Version %s by Chris Kennedy (C) 2002\n",
                  version);
        if(mailfrom != NULL && ((found_virus == 1 && virus_header.sender > 0) ||
                                (match != NO_MATCH && spam_header.sender > 0)))
          fprintf(vf, "X-BlackHole-Sender: %s\n", mailfrom);
        if(iprelay != NULL && ((found_virus == 1 && virus_header.relay > 0) ||
                               (match != NO_MATCH && spam_header.relay > 0)))
          fprintf(vf, "X-BlackHole-Relay: %s\n", iprelay);
        if(matches[match] != NULL &&
           ((found_virus == 1 && virus_header.match > 0) ||
            (match != NO_MATCH && spam_header.match > 0)))
          fprintf(vf, "X-BlackHole-Match: %s\n", matches[match]);
        if(log_info != NULL && ((found_virus == 1 && virus_header.status > 0) ||
                                (match != NO_MATCH && spam_header.status > 0)))
          fprintf(vf, "X-BlackHole-Info: %s\n", log_info);
        if(virusscan > 0) {
          if(virus_ret > 0 && virus_header.status > 0)
            fprintf(vf, "X-BlackHole-Virus-Status: %s\n", viruses[virus_ret]);
          if(virus_type != NULL && virus_header.type > 0)
            fprintf(vf, "X-BlackHole-Virus-Type: %s\n", virus_type);
        }
      }
      eoh = 1;
    }
    if(fwd != NULL) {
      rc = crlf_write(sd, buffer, my_strlen(buffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        fclose(tf);
        return 1;
      }
    } else
      fputs(buffer, vf);
  }

  /* Mail forwarding */
  if(fwd != NULL) {
    /* Write a '.' and to the Socket */
    rc = write(sd, "\r\n.\r\nquit\r\n", my_strlen("\r\n.\r\nquit\r\n"));
    if(bh_assert(rc <= 0)) {
      close(sd);
      fclose(tf);
      return 1;
    }
    /* Read from the Socket */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof(iobuf));
    strsize = my_strlen(iobuf);
    my_strlcpy(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    /* Check for 250 */
    if(bh_assert(strstr(netbuffer, "250 ") == NULL)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      fclose(tf);
      return 1;
    }

    /* Close Socket */
    close(sd);
    free(netbuffer);
  } else if(qmail_queue == 1 || qmail_qfilter == 1) {
    fputc('\n', vf);
#ifndef QMAIL_QFILTER
    rewind(vf);
    while(fgets(buffer, MAX_INPUT_LINE + 1, vf))
      fputs(buffer, stdout);
#endif
    fclose(vf);
#ifndef QMAIL_QFILTER
    unlink(vfile);
#endif
  } else {
    fputc('\n', vf);
    fclose(vf);
  }

  /* Close Tmp File */
  fclose(tf);

  /* Free Buffer */
  free(buffer);

  /* OK */
  return 0;
}

int bcc_alert(char *mailfrom, char *iprelay, char *relay, char *fwd, char *bcc)
{
  struct hostent *h;
  struct sockaddr_in srcaddr, dstaddr;
  char iobuf[1024], *netbuffer = NULL;
  char *helo, *mfrm, *rcpt = NULL, *bccto = NULL;
  char *buffer;
  int sd = 0, rc = 0;
  FILE *tf = NULL;
  int i = 0, h_foundip = 0;
  char *h_tstamp = NULL, *h_iprelay = NULL, *h_iphost = NULL;


  if(fwd != NULL || bcc != NULL) {
    buffer = malloc(MAX_INPUT_LINE + 1);
    if(buffer == NULL)
      return 1;

    netbuffer = malloc(MAX_INPUT_LINE + 1);
    if(netbuffer == NULL)
      return 1;

    /* helo */
    strsize = my_strlen(hostname) + 7;
    helo = malloc(strsize + 1);
    if(helo == NULL)
      return 1;
    snprintf(helo, strsize + 1, "helo %s\r\n", hostname);

    /* mail from: */
    if(mailfrom != NULL) {
      strsize = my_strlen(mailfrom) + 15;
      mfrm = malloc(strsize + 1);
      if(mfrm == NULL)
        return 1;
      snprintf(mfrm, strsize + 1, "mail from: <%s>\r\n", mailfrom);
    } else {
      strsize = 15;
      mfrm = malloc(strsize + 1);
      if(mfrm == NULL)
        return 1;
      snprintf(mfrm, strsize + 1, "mail from: <>\r\n");
    }

    /* rcpt to: */
    if(fwd != NULL && my_strlen(fwd) > 0) {
      strsize = my_strlen(fwd) + 13;
      rcpt = malloc(strsize + 1);
      if(rcpt == NULL)
        return 1;
      snprintf(rcpt, strsize + 1, "rcpt to: <%s>\r\n", fwd);
    }

    /*
       TKONG : changed rcpt BCC: to rcpt TO:. rcpt bcc: is not in RFC 821
               and was not working. 20021021
    */
    /* bcc to: */
    if(bcc != NULL) {
      if((bcc != NULL && fwd != NULL) && (strcmp(bcc,fwd) != 0)) {
        strsize = my_strlen(bcc) + 13;
        bccto = malloc(strsize + 1);
        if(bccto == NULL)
          return 1;
        snprintf(bccto, strsize + 1, "rcpt to: <%s>\r\n", bcc);
      }
    }

    /* Setup SMTP Connection */
    h = gethostbyname(relay);
    if(bh_assert(h == NULL))
      return 1;
    dstaddr.sin_family = h->h_addrtype;
    memcpy((char *) &dstaddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
    dstaddr.sin_port = htons(SMTP_FWD_PORT);

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if(bh_assert(sd < 0))
      return 1;

    srcaddr.sin_family = AF_INET;
    srcaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    srcaddr.sin_port = htons(0);

    rc = bind(sd, (struct sockaddr *) &srcaddr, sizeof(srcaddr));
    if(bh_assert(rc < 0))
      return 1;

    rc = connect(sd, (struct sockaddr *) &dstaddr, sizeof(dstaddr));
    if(bh_assert(rc < 0))
      return 1;

    /* Read from the Socket */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof iobuf);
    strsize = my_strlen(iobuf);
    my_strlcat(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    /* get 220 or leave */
    if(bh_assert(strncmp(netbuffer, "220 ", 3) != 0)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      return 1;
    }

    /* Write to the HELO command to the Socket */
    rc = crlf_write(sd, helo, (my_strlen(helo)));
    if(bh_assert(rc <= 0)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      return 1;
    }
    free(helo);

    /* Read from the Socket, get 250 or leave */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof(iobuf));
    strsize = my_strlen(iobuf);
    my_strlcat(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    if(bh_assert(strstr(netbuffer, "250 ") == NULL)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      return 1;
    }

    /* Write to the MAIL FROM command to the Socket */
    rc = crlf_write(sd, mfrm, (my_strlen(mfrm)));
    if(bh_assert(rc <= 0)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      return 1;
    }
    free(mfrm);

    /* Read from the Socket, get 250 or leave */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof(iobuf));
    strsize = my_strlen(iobuf);
    my_strlcat(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    if(bh_assert(strstr(netbuffer, "250 ") == NULL)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      return 1;
    }

    /* Write to the RCPT TO command to the Socket */
    if(rcpt != NULL) {
      rc = crlf_write(sd, rcpt, (my_strlen(rcpt)));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
      /* Read from the Socket, get 250 or leave */
      strcpy(netbuffer, "");
      rc = read(sd, iobuf, sizeof(iobuf));
      strsize = my_strlen(iobuf);
      my_strlcat(netbuffer, iobuf, strsize + 1);
      netbuffer[strsize] = (char) '\0';

      if(bh_assert(strstr(netbuffer, "250 ") == NULL)) {
#if WITH_DEBUG == 1
        if(DEBUG) {
          if(netbuffer != NULL)
            fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
        }
#endif
        close(sd);
        return 1;
      }
      free(rcpt);
    }

    /* Write to the BCC TO command to the Socket */
    if(bccto != NULL) {
      rc = crlf_write(sd, bccto, (my_strlen(bccto)));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
      /* Read from the Socket, get 250 or leave */
      strcpy(netbuffer, "");
      rc = read(sd, iobuf, sizeof(iobuf));
      strsize = my_strlen(iobuf);
      my_strlcat(netbuffer, iobuf, strsize + 1);
      netbuffer[strsize] = (char) '\0';

      if(bh_assert(strstr(netbuffer, "250 ") == NULL)) {
#if WITH_DEBUG == 1
        if(DEBUG) {
          if(netbuffer != NULL)
            fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
        }
#endif
        close(sd);
        return 1;
      }
      free(bccto);
    }

    /* Write DATA to the Socket */
    rc = crlf_write(sd, "data\r\n", my_strlen("data\r\n"));
    if(bh_assert(rc <= 0))
      return 1;

    /* Read from the Socket, get 354 or leave */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof(iobuf));
    strsize = my_strlen(iobuf);
    my_strlcat(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    if(bh_assert(strstr(netbuffer, "354 ") == NULL)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
        if(mailfrom != NULL) 
          fprintf(stderr, "SMTP mailfrom: '%s'\n", mailfrom);
        if(fwd != NULL) 
          fprintf(stderr, "SMTP rcpt to: '%s'\n", fwd);
        if(bcc != NULL) 
          fprintf(stderr, "SMTP rcpt bcc: '%s'\n", bcc);
      }
#endif
      close(sd);
      return 1;
    }

    /* Insert X-BlackHole: Headers */

    /* version header */
    if((found_virus == 1 && virus_header.version > 0) ||
       (match != NO_MATCH && spam_header.version > 0)) {
      strsize = my_strlen(version) + 49;
      netbuffer[strsize] = (char) '\0';
      snprintf(netbuffer, strsize + 1,
               "X-BlackHole: Version %s by Chris Kennedy (C) 2002\r\n",
               version);
      rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
    }
    /* sender header */
    if(mailfrom != NULL && ((found_virus == 1 && virus_header.sender > 0) ||
                            (match != NO_MATCH && spam_header.sender > 0))) {
      strsize = my_strlen(mailfrom) + 22;
      netbuffer[strsize] = (char) '\0';
      snprintf(netbuffer, strsize + 1, "X-BlackHole-Sender: %s\r\n", mailfrom);
      rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
    }
    /* iprelay header */
    if(iprelay != NULL && ((found_virus == 1 && virus_header.relay > 0) ||
                           (match != NO_MATCH && spam_header.relay > 0))) {
      strsize = my_strlen(iprelay) + 23;
      netbuffer[strsize] = (char) '\0';
      snprintf(netbuffer, strsize + 1, "X-BlackHole-Relay: %s\r\n", iprelay);
      rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
    }
    /* match */
    if(matches[match] != NULL &&
       ((found_virus == 1 && virus_header.match > 0) ||
        (match != NO_MATCH && spam_header.match > 0))) {
      strsize = my_strlen(matches[match]) + 21;
      netbuffer[strsize] = (char) '\0';
      snprintf(netbuffer, strsize + 1,
               "X-BlackHole-Match: %s\r\n", matches[match]);
      rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
    }
    /* info */
    if(log_info != NULL && ((found_virus == 1 && virus_header.status > 0) ||
                            (match != NO_MATCH && spam_header.status > 0))) {
      strsize = my_strlen(log_info) + 20;
      netbuffer[strsize] = (char) '\0';
      snprintf(netbuffer, strsize + 1, "X-BlackHole-Info: %s\r\n", log_info);
      rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
    }
    if(virusscan > 0) {
      /* virus status */
      if(virus_ret > 0 && virus_header.status > 0) {
        strsize = my_strlen(viruses[virus_ret]) + 28;
        netbuffer[strsize] = (char) '\0';
        snprintf(netbuffer, strsize + 1,
                 "X-BlackHole-Virus-Status: %s\r\n", viruses[virus_ret]);
        rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
        if(bh_assert(rc <= 0)) {
          close(sd);
          return 1;
        }
      }
      /* virus type */
      if(virus_type != NULL && virus_header.type > 0) {
        strsize = my_strlen(virus_type) + 26;
        netbuffer[strsize] = (char) '\0';
        snprintf(netbuffer, strsize + 1,
                 "X-BlackHole-Virus-Type: %s\r\n", virus_type);
        rc = crlf_write(sd, netbuffer, my_strlen(netbuffer));
        if(bh_assert(rc <= 0)) {
          close(sd);
          return 1;
        }
      }
    }

    /* Create message subject */
    strsize = my_strlen(virus_type) + my_strlen(mailfrom) + 23;
    if(strsize > MAX_INPUT_LINE)
      strsize = MAX_INPUT_LINE;
    snprintf(buffer,
             strsize + 1, "Subject: [%s Virus from %s]", virus_type, mailfrom);

    /* Write out message subject */
    rc = crlf_write(sd, buffer, my_strlen(buffer));
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }

    /* Write a '\r\n\r\n' to the Socket */
    rc = write(sd, "\r\n\r\n", my_strlen("\r\n\r\n"));
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }

    /* Create message body */
    /* timestamp */
    strsize = my_strlen(timestamp) + 6;
    if(strsize > MAX_INPUT_LINE)
      strsize = MAX_INPUT_LINE;
    snprintf(buffer, strsize + 1, "Date: %s", timestamp);

    rc = crlf_write(sd, buffer, my_strlen(buffer));
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }

    /* virus_type */
    strsize = my_strlen(virus_type) + 7;
    if(strsize > MAX_INPUT_LINE)
      strsize = MAX_INPUT_LINE;
    snprintf(buffer, strsize + 1, "Virus: %s", virus_type);

    rc = crlf_write(sd, buffer, my_strlen(buffer));
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }

    /* mailfrom */
    if(mailfrom != NULL) {
      strsize = my_strlen(mailfrom) + 6;
      if(strsize > MAX_INPUT_LINE)
        strsize = MAX_INPUT_LINE;
      snprintf(buffer, strsize + 1, "From: %s", mailfrom);
  
      rc = crlf_write(sd, buffer, my_strlen(buffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
    }

    /* rcptto */
    if(rcptto != NULL) {
      strsize = my_strlen(rcptto) + 4;
      if(strsize > MAX_INPUT_LINE)
        strsize = MAX_INPUT_LINE;
      snprintf(buffer, strsize + 1, "To: %s", rcptto);

      rc = crlf_write(sd, buffer, my_strlen(buffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
    }

    h_tstamp = malloc(MAX_INPUT_LINE + 1);
    if(bh_assert(h_tstamp == NULL)) {
      close(sd);
      return 1;
    }

    h_iprelay = malloc(MAX_RELAY_SIZE + 1);
    if(bh_assert(h_iprelay == NULL)) {
      close(sd);
      return 1;
    }

    h_iphost = malloc(MAX_INPUT_LINE + 1);
    if(bh_assert(h_iphost == NULL)) {
      close(sd);
      return 1;
    }

    /* open tmp file with headers in it for reading */
    tf = fopen(tmp_file, "r");
    if(bh_assert(tf == NULL))
      return 1;

    /* headers title */
    strsize = 21;
    snprintf(buffer, strsize + 1, "\r\nOriginal Headers:\r\n");
    rc = write(sd, buffer, my_strlen(buffer));
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }

    /* Loop through and output original headers */
    while(fgets(buffer, MAX_INPUT_LINE + 1, tf) != '\0') {
      rc = crlf_write(sd, buffer, my_strlen(buffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        fclose(tf);
        return 1;
      }
      /* Extract headers date and relay */
      if(h_foundip == 1) {
        h_foundip = 0;    
        if(strncmp(buffer, "  by ", 5) == 0) {
#if WITH_DEBUG == 1
          if(DEBUG)
            fprintf(stderr, "Extracting line for tstamp BCC: '%s'\n", buffer);
#endif
          extract_tstamp(buffer, h_tstamp);
#if WITH_DEBUG == 1
          if(DEBUG)
            fprintf(stderr, " Found: h_tstamp '%s' \n", h_tstamp);
#endif
        }
      } else if(strncmp(buffer, "Received: from ", 15) == 0) {
        h_foundip = 1;
        checkreverse = 1;
#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, "Extracting line for BCC: '%s'\n", buffer);
#endif
        regexip(buffer, h_iprelay, h_iphost);
#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, " Found: h_iphost '%s' \n", h_iphost);
#endif
      }
      /* Only copy header, sane limit of 100 lines */
      if(strncmp(buffer, "\n", 1) == 0 || i > 100)
        break;
      else
        i++;
    }
    /* Close tmp msg */
    fclose(tf);

    /* header timestamp */
    if(h_tstamp != NULL) {
      strsize = my_strlen(h_tstamp) + 13;
      if(strsize > MAX_INPUT_LINE)
        strsize = MAX_INPUT_LINE;
      snprintf(buffer, strsize + 1, "Header Date: %s", h_tstamp);

      rc = crlf_write(sd, buffer, my_strlen(buffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
    }
    free(h_tstamp);

    /* header relay */
    if(h_iprelay != NULL) {
      strsize = my_strlen(h_iprelay) + 11;
      if(strsize > MAX_INPUT_LINE)
        strsize = MAX_INPUT_LINE;
      snprintf(buffer, strsize + 1, "Header IP: %s", h_iprelay);

      rc = crlf_write(sd, buffer, my_strlen(buffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
    }
    free(h_iprelay);

    /* header host */
    if(h_iphost != NULL) {
      strsize = my_strlen(h_iphost) + 13;
      if(strsize > MAX_INPUT_LINE)
        strsize = MAX_INPUT_LINE;
      snprintf(buffer, strsize + 1, "Header Host: %s", h_iphost);

      rc = crlf_write(sd, buffer, my_strlen(buffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
    }
    free(h_iphost);

    /* Write a '.' and to the Socket */
    rc = write(sd, "\r\n.\r\nquit\r\n", my_strlen("\r\n.\r\nquit\r\n"));
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }
    /* Read from the Socket */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof(iobuf));
    strsize = my_strlen(iobuf);
    my_strlcpy(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    /* Check for 250 */
    if(bh_assert(strstr(netbuffer, "250 ") == NULL)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      return 1;
    }

    /* Close Socket */
    close(sd);
    free(buffer);
    free(netbuffer);
  } else
    return 1;

  /* OK */
  return 0;
}

int pfilter_put(char *message)
{
  int pid, status;

  freopen(message, "r", stdin);

#if WITH_DEBUG == 1
    if(DEBUG) {
      int cnt;
      fprintf(stderr, "Running POSTFIX:\n %s", sendmail_bin);
      for(cnt = 0;pfilter_args[cnt] != NULL;cnt++)
        fprintf(stderr, " %s", pfilter_args[cnt]);
      fprintf(stderr, "\n"); 
      fprintf(stderr, "On file:\n %s\n", message); 
    }
#endif

  /* Fork for Sendmail */
  pid = fork();
  if(pid == -1)
    return 0;
  if(pid == 0) {
    /* Run Command */
    execv(sendmail_bin, pfilter_args);
    exit(127);
  }
  do {
    if(waitpid(pid, &status, 0) == -1) {
      if(errno != EINTR)
        return -1;
    } else {
      status >>= 8;
      status &= 0xFF;
      if(bh_assert(status != 0))
        return status;
      break;
    }
  } while(1);

  return 0;
}

int smtp_bounce(char *mailfrom, char *rcptto, char *relay, char *cust_msg)
{
  struct hostent *h;
  struct sockaddr_in srcaddr, dstaddr;
  char iobuf[1024], *netbuffer = NULL;
  char *helo, *mfrm, *rcpt = NULL;
  char *buffer;
  int sd = 0, rc = 0;
  FILE *tf = NULL;
  int i = 0;

  if(mailfrom != NULL && my_strlen(mailfrom) > 0) {
    buffer = malloc(MAX_INPUT_LINE + 1);
    if(buffer == NULL)
      return 1;

    netbuffer = malloc(MAX_INPUT_LINE + 1);
    if(netbuffer == NULL)
      return 1;

    /* helo */
    strsize = my_strlen(hostname) + 7;
    helo = malloc(strsize + 1);
    if(helo == NULL)
      return 1;
    snprintf(helo, strsize + 1, "helo %s\r\n", hostname);

    /* mail from: */
    /*if(rcptto != NULL) {
      strsize = my_strlen(rcptto) + 15;
      mfrm = malloc(strsize + 1);
      if(mfrm == NULL)
        return 1;
      snprintf(mfrm, strsize + 1, "mail from: <%s>\r\n", rcptto);
    } else {*/
      strsize = 15;
      mfrm = malloc(strsize + 1);
      if(mfrm == NULL)
        return 1;
      snprintf(mfrm, strsize + 1, "mail from: <>\r\n");
    /*}*/

    /* rcpt to: */
    strsize = my_strlen(mailfrom) + 13;
    rcpt = malloc(strsize + 1);
    if(rcpt == NULL)
      return 1;
    snprintf(rcpt, strsize + 1, "rcpt to: <%s>\r\n", mailfrom);

    /* Setup SMTP Connection */
    h = gethostbyname(relay);
    if(bh_assert(h == NULL))
      return 1;
    dstaddr.sin_family = h->h_addrtype;
    memcpy((char *) &dstaddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
    dstaddr.sin_port = htons(SMTP_FWD_PORT);

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if(bh_assert(sd < 0))
      return 1;

    srcaddr.sin_family = AF_INET;
    srcaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    srcaddr.sin_port = htons(0);

    rc = bind(sd, (struct sockaddr *) &srcaddr, sizeof(srcaddr));
    if(bh_assert(rc < 0))
      return 1;

    rc = connect(sd, (struct sockaddr *) &dstaddr, sizeof(dstaddr));
    if(bh_assert(rc < 0))
      return 1;

    /* Read from the Socket */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof iobuf);
    strsize = my_strlen(iobuf);
    my_strlcat(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    /* get 220 or leave */
    if(bh_assert(strncmp(netbuffer, "220 ", 3) != 0)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      return 1;
    }

    /* Write to the HELO command to the Socket */
    rc = crlf_write(sd, helo, (my_strlen(helo)));
    if(bh_assert(rc <= 0)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      return 1;
    }
    free(helo);

    /* Read from the Socket, get 250 or leave */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof(iobuf));
    strsize = my_strlen(iobuf);
    my_strlcat(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    if(bh_assert(strstr(netbuffer, "250 ") == NULL)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      return 1;
    }

    /* Write to the MAIL FROM command to the Socket */
    rc = crlf_write(sd, mfrm, (my_strlen(mfrm)));
    if(bh_assert(rc <= 0)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      return 1;
    }
    free(mfrm);

    /* Read from the Socket, get 250 or leave */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof(iobuf));
    strsize = my_strlen(iobuf);
    my_strlcat(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    if(bh_assert(strstr(netbuffer, "250 ") == NULL)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      return 1;
    }

    /* Write to the RCPT TO command to the Socket */
    if(rcpt != NULL) {
      rc = crlf_write(sd, rcpt, (my_strlen(rcpt)));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
      /* Read from the Socket, get 250 or leave */
      strcpy(netbuffer, "");
      rc = read(sd, iobuf, sizeof(iobuf));
      strsize = my_strlen(iobuf);
      my_strlcat(netbuffer, iobuf, strsize + 1);
      netbuffer[strsize] = (char) '\0';

      if(bh_assert(strstr(netbuffer, "250 ") == NULL)) {
#if WITH_DEBUG == 1
        if(DEBUG) {
          if(netbuffer != NULL)
            fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
        }
#endif
        close(sd);
        return 1;
      }
      free(rcpt);
    }

    /* Write DATA to the Socket */
    rc = crlf_write(sd, "data\r\n", my_strlen("data\r\n"));
    if(bh_assert(rc <= 0))
      return 1;

    /* Read from the Socket, get 354 or leave */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof(iobuf));
    strsize = my_strlen(iobuf);
    my_strlcat(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    if(bh_assert(strstr(netbuffer, "354 ") == NULL)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
        if(rcptto != NULL) 
          fprintf(stderr, "SMTP mailfrom: '%s'\n", rcptto);
        if(mailfrom != NULL) 
          fprintf(stderr, "SMTP rcpt to: '%s'\n", mailfrom);
      }
#endif
      close(sd);
      return 1;
    }

    /* Create pretty headers */
    if(mailfrom != NULL) { 
      snprintf(buffer, MAX_INPUT_LINE - 1, "To: %s", mailfrom);
      rc = crlf_write(sd, buffer, my_strlen(buffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
    }
    if(rcptto != NULL) {
      snprintf(buffer, MAX_INPUT_LINE - 1, "From: %s", rcptto);
      rc = crlf_write(sd, buffer, my_strlen(buffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        return 1;
      }
    }
    snprintf(buffer, 
         MAX_INPUT_LINE - 1, "Subject: failure notice");
    rc = crlf_write(sd, buffer, my_strlen(buffer));
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }

    /* Write a '\r\n\r\n' to the Socket */
    rc = write(sd, "\r\n\r\n", my_strlen("\r\n\r\n"));
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }

    /* Create message body */
    /* Recipient address that bounced */
    strsize = my_strlen(rcptto) + 3;
    if(strsize > MAX_INPUT_LINE)
      strsize = MAX_INPUT_LINE;
    snprintf(buffer, strsize + 1, "<%s>:", rcptto);

    rc = crlf_write(sd, buffer, my_strlen(buffer));
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }

    /* virus_type */
    strsize = my_strlen(cust_msg);
    if(strsize > MAX_INPUT_LINE)
      strsize = MAX_INPUT_LINE;
    snprintf(buffer, strsize + 1, "%s", cust_msg);

    rc = write(sd, buffer, my_strlen(buffer));
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }
    
    /* End Bounce Line */
    rc = write(sd, "\r\n", 2);
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }

    /* open tmp file with headers in it for reading */
    tf = fopen(tmp_file, "r");
    if(bh_assert(tf == NULL))
      return 1;

    /* headers title */
    strsize = 57;
    snprintf(buffer, strsize + 1, 
         "\r\n--- Below this line is a copy of the message headers.\r\n");
    rc = write(sd, buffer, my_strlen(buffer));
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }

    /* Spacer */
    rc = write(sd, "\r\n", 2);
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }

    /* Loop through and output original headers */
    while(fgets(buffer, MAX_INPUT_LINE + 1, tf) != '\0') {
      rc = crlf_write(sd, buffer, my_strlen(buffer));
      if(bh_assert(rc <= 0)) {
        close(sd);
        fclose(tf);
        return 1;
      }

      /* Only copy header, sane limit of 100 lines */
      if(strncmp(buffer, "\n", 1) == 0 || i > 100)
        break;
      else
        i++;
    }
    /* Close tmp msg */
    fclose(tf);

    /* Write a '.' and to the Socket */
    rc = write(sd, "\r\n.\r\nquit\r\n", my_strlen("\r\n.\r\nquit\r\n"));
    if(bh_assert(rc <= 0)) {
      close(sd);
      return 1;
    }
    /* Read from the Socket */
    strcpy(netbuffer, "");
    rc = read(sd, iobuf, sizeof(iobuf));
    strsize = my_strlen(iobuf);
    my_strlcpy(netbuffer, iobuf, strsize + 1);
    netbuffer[strsize] = (char) '\0';

    /* Check for 250 */
    if(bh_assert(strstr(netbuffer, "250 ") == NULL)) {
#if WITH_DEBUG == 1
      if(DEBUG) {
        if(netbuffer != NULL)
          fprintf(stderr, "SMTP Server returned: '%s'!!!\n", netbuffer);
      }
#endif
      close(sd);
      return 1;
    }

    /* Close Socket */
    close(sd);
    free(buffer);
    free(netbuffer);
  } else
    return 1;

  /* OK */
  return 0;
}

/* Compare Command entered against minimal length given for it */
int cmd_cmp(char *buffer, char *cmd, int minlength)
{
  char *bp = buffer;
  char *cp = cmd;
  int cur_pos = 1, maxlength;

  maxlength = my_strlen(cmd);

  /* Allow the '--' style args to work */
  if(strncmp(buffer, "--", 2) == 0 && my_strlen(buffer) > 2) {
    maxlength++;
    cur_pos++;
    bp++;
    minlength = maxlength;
  }

  if(my_strlen(buffer) > maxlength)
    return 1;
  else if(my_strlen(buffer) < minlength)
    return -1;

  for(; (*bp) && (*cp); bp++, cp++, cur_pos++) {
    if(cur_pos > maxlength)
      return 1;
    else if(*bp == '\n')
      break;
    else if(*bp != *cp)
      return -1;
  }

  return 0;
}

/* Check args in a Lazy Way */
int crlf_write(int fd, char *buffer, int len)
{
  int count;
  int rc;
  char *buffer2;

  if(buffer == NULL)
    return 0;

  buffer2 = malloc(my_strlen(buffer) + 3);
  if(buffer2 == NULL)
    return 0;

  for(count = 0; buffer[count] != '\0' && count < len; count++) {
    if(buffer[count] != '\n' && buffer[count] != '\r')
      buffer2[count] = (char) buffer[count];
    else
      break;
  }
  buffer2[count++] = (char) '\r';
  buffer2[count++] = (char) '\n';
  buffer2[count] = (char) '\0';

  rc = write(fd, buffer2, my_strlen(buffer2));
  free(buffer2);

  return rc;
}

/* Enable Core Dumping */
void enable_core(void)
{
  struct rlimit cur_rlimit;

  cur_rlimit.rlim_max = MAX_CORE_SIZE;
  setrlimit(RLIMIT_CORE, &cur_rlimit);
}

/* for bh_assert define */
int one_out(int expr, int linenum, char *rev) {
  fprintf(stderr,"%d: %s ERROR(%d)!\n",
        linenum, rev, expr);
  return 1;
}

/* Create Maildir in Config Interface */
int mk_maildir(char *location)
{
  char *buffer;

  if(use_maildir > 0 || sendmail < 1) {
    buffer = malloc(strlen(location) + 4 + 1);
    if(buffer == NULL)
      return 1;

    /* Base of Maildir */
    fprintf(stdout, " creating %s\n", location);
    mkdir(location,0700);

    /* ./Maildir/tmp/ */
    snprintf(buffer,(strlen(location) + 4 + 1), "%s/tmp", location);
    fprintf(stdout, " creating %s\n", buffer);
    mkdir(buffer,0700);
    
    /* ./Maildir/cur/ */
    snprintf(buffer,(strlen(location) + 4 + 1), "%s/cur", location);
    fprintf(stdout, " creating %s\n", buffer);
    mkdir(buffer,0700);

    /* ./Maildir/new/ */
    snprintf(buffer,(strlen(location) + 4 + 1), "%s/new", location);
    fprintf(stdout, " creating %s\n", buffer);
    mkdir(buffer,0700);

    free(buffer);
  }
  return 0;
}

int get_choice(char *strang) 
{
  int i;
  int maxpos = 1;
  char *argbuffer[3];

  for(i=0;strang[i] != '\0';i++)
    if(strang[i] == ' ' && (i > 0 && strang[i-1] != ' ')) 
      maxpos++;
  
  if(maxpos == 1) {
    if((cmd_cmp(strang,"?",1) == 0) || (cmd_cmp(strang,"help",1) == 0))
      cfg_sec = H;
    else if(cmd_cmp(strang,"config",1) == 0)
      cfg_sec = C;
    else if(cmd_cmp(strang,"exit", 1) == 0 || cmd_cmp(strang,"quit", 1) == 0)
      cfg_sec = E;
    else
      cfg_sec = -1;
  } else if(maxpos == 2) {
    argbuffer[0] = malloc(256);
    argbuffer[1] = malloc(256);
    argbuffer[2] = NULL;
    sscanf(strang, "%s%*[ ]%s", argbuffer[0], argbuffer[1]);
    if((cmd_cmp(argbuffer[0],"show",1) == 0)) {
      if((cmd_cmp(argbuffer[1], "config", 1) == 0))
        cfg_sec = SC; 
      else if((cmd_cmp(argbuffer[1], "maildir", 1) == 0))
        cfg_sec = SM;
      else if((cmd_cmp(argbuffer[1], "internals", 1) == 0))
        cfg_sec = SI;
      else if((cmd_cmp(argbuffer[1], "rbl", 1) == 0))
        cfg_sec = SR;
      else
       cfg_sec = -1; 
    } else if((cmd_cmp(argbuffer[0],"make",1) == 0)) {
      if((cmd_cmp(argbuffer[1], "maildir", 1) == 0))
        cfg_sec = MM;
      else
       cfg_sec = -1;
    } else if(cmd_cmp(argbuffer[0], "config",1) == 0) {
      if((cmd_cmp(argbuffer[1], "terminal", 1) == 0))
        cfg_sec = CT;
    } else
     cfg_sec = -1;
  } else if(maxpos == 3) {
    argbuffer[0] = malloc(256);
    argbuffer[1] = malloc(256);
    argbuffer[2] = malloc(256);
    argbuffer[3] = NULL;
    sscanf(strang, 
         "%s%*[ ]%s%*[ ]%s", argbuffer[0], argbuffer[1], argbuffer[2]);
    if((cmd_cmp(argbuffer[0],"show",1) == 0)) {
      if((cmd_cmp(argbuffer[1], "config", 1) == 0) && 
        (cmd_cmp(argbuffer[2], "file", 1) == 0)) 
        cfg_sec = SCF; 
      else
       cfg_sec = -1; 
    } else
     cfg_sec = -1;
  } else
    fprintf(stderr, "Error, too many arguments!\n\n");

  if(cfg_sec != -1)
    return cfg_sec; 

  return 99999;
}

/* Configuration Interface */
void config(void) 
{
  char *ibuf;
  char *menu =
"Options can be abbreviated to one charater per word.\n\n"
" config                Configure options, lists descriptions/current value.\n"
" config terminal       Go into configure prompt, without menu of options.\n"
"\n"
" show config           Show current running config.\n"
" show config file      Show current config file\n"
" show maildir          Show ok/spam/virus Maildir/Mailboxes of current user.\n"
" show internals        Show build options.\n"
" show rbl              Show list of RBL servers to use, and DNS server.\n"
"\n"
" make maildir          Create ok/spam/virus Maildir's for current user.\n"
"\n"
" exit                  Leave the config interface.\n";
  int i;

  ibuf = malloc(255 + 1);
  if(bh_assert(ibuf == NULL))
    exit(1); 

  fprintf(stderr, "BlackHole Version %s CLI\n\n", version);
  fprintf(stderr, " '?' will print the help menu.\n\n");
  fprintf(stderr, "%s> ", progname);
  while((ibuf = fgets(ibuf,255+1,stdin)) != '\0') {
    int jx;
    /* clean input */
    if(ibuf[0] == ' ') {
      for(i = 0;ibuf[i] == ' ';i++);
      for(jx = 0; ibuf[i] != '\0';jx++,i++)
        ibuf[jx] = ibuf[i];
      ibuf[jx] = '\0';
    }
    for(i = 0; ibuf[i] != '\n' && ibuf[i] != '\0'; i++);
    ibuf[i] = '\0';
    if(ibuf[i-1] == ' ') {
      i--;
      while(ibuf[i--] == ' ');
      ibuf[i] = '\0';
    }

    cfg_sec = get_choice(ibuf);
    if(DEBUG)
      fprintf(stderr, "Choice: %d\n", (int)cfg_sec);

    /* parse input */
    if(cfg_sec == E) {
      fprintf(stdout, " Exiting...\n");
      exit(0); 
    } else if(cfg_sec == MM) {
      char *dirbuf = NULL;

      if(sendmail == 1 && use_maildir == 0 && spooldir != NULL) {
        strsize = my_strlen(homedir) + my_strlen(spooldir) + 1;
        dirbuf = malloc(strsize + 1);
        if(dirbuf == NULL)
          exit(1);
        snprintf(dirbuf, strsize + 1, "%s/%s", homedir, spooldir);
        fprintf(stdout, " creating %s\n", dirbuf);
        mkdir(dirbuf,0700);
      } else {
        /* make maildir */
        strsize = my_strlen(homedir) + my_strlen(maildir) + 1;
        dirbuf = malloc(strsize + 1);
        if(dirbuf == NULL)
          exit(1);
        snprintf(dirbuf, strsize + 1, "%s/%s", homedir, maildir);
        if(bh_assert(mk_maildir(dirbuf) != 0))
          exit(1);
        /* make spam maildir */
        strsize = my_strlen(homedir) + my_strlen(maildir) + 
             my_strlen(spam_mail_dir) + 2; 
        dirbuf = malloc(strsize + 1);
        if(dirbuf == NULL)
          exit(1);
        snprintf(dirbuf, 
             strsize + 1, "%s/%s/%s", homedir, maildir, spam_mail_dir);
        if(bh_assert(mk_maildir(dirbuf) != 0))
          exit(1);
        /* make virus maildir */
        strsize = my_strlen(homedir) + my_strlen(maildir) + 
             my_strlen(virus_mail_dir) + 2; 
        dirbuf = malloc(strsize + 1);
        if(dirbuf == NULL)
          exit(1);
        snprintf(dirbuf, 
             strsize + 1, "%s/%s/%s", homedir, maildir, virus_mail_dir);
        if(bh_assert(mk_maildir(dirbuf) != 0))
          exit(1);
      }
    } else if(cfg_sec == SM) {
      if(sendmail == 1 && use_maildir == 0) {
        if(spooldir != NULL && my_strlen(spooldir) > 0) {
          fprintf(stdout, " Mailbox:        %s/%s\n", sendmail_dir, username);
          fprintf(stdout, " Spam Mailbox:   %s/%s/%s\n", 
               homedir, spooldir, spam_mail_box);
          fprintf(stdout, " Virus Mailbox:  %s/%s/%s\n", 
               homedir, spooldir, virus_mail_box);
          fprintf(stdout, " Spool Dir: %s\n", spooldir);
        } else {
          fprintf(stdout, " Mailbox:        %s/%s\n", sendmail_dir, username);
          fprintf(stdout, " Spam Mailbox:   %s/%s\n", homedir, spam_mail_box);
          fprintf(stdout, " Virus Mailbox:  %s/%s\n", homedir, virus_mail_box);
        }
      } else {
        fprintf(stdout, " Maildir:        %s/%s/\n", homedir, maildir);
        fprintf(stdout, " Spam Maildir:   %s/%s/%s/\n", 
             homedir, maildir, spam_mail_dir);
        fprintf(stdout, " Virus Maildir:  %s/%s/%s/\n", 
             homedir, maildir, virus_mail_dir);
      }
    } else if(cfg_sec == SI) {
      internal_settings();
    } else if(cfg_sec == SR) {
      printf("Current RBL Lists:\n\n");
      for(i = 0; rblhosts[i] != NULL; i++)
        fprintf(stdout, " (%d). %s\n", i, rblhosts[i]);
      if(dns_srv != NULL)
        fprintf(stdout, " DNS Server: %s\n\n", dns_srv);
      else
        fprintf(stdout, "\n");
      fprintf(stdout, " Current Level: %d\n", level);
    } else if(cfg_sec == C) {
      cfgmenu();
      fprintf(stdout, "To stay in cmdprompt use 'config terminal'.\n");
    } else if(cfg_sec == CT) {
      fprintf(stdout, "Possible options:\n");
      fprintf(stdout, " quit     exit prompt.\n");
      fprintf(stdout, " list     list options index.\n");
      while(bh_pager_in(1) != 'q');
      fprintf(stdout, "\n");
    } else if(cfg_sec == SCF) {
      fprintf(stdout, " Reading %s Config File...\n", config_file);
      sleep(1); 
      readconfig(RC_SHOW);
    } else if(cfg_sec == SC) {
      int count = 1;
      fprintf(stdout, " Current Config...\n");
      for(i = 0; cfg[i].section != NULL; i++) {
        count++;
        fprintf(stdout, "#\n");
        if((count % 20) == 0)
          bh_pager();
        count++;
        fprintf(stdout, "[%s]\n", cfg[i].section);
        if((count % 20) == 0)
          bh_pager();
        strsize = my_strlen(cfg[i].info);
        /* Current Settings */
        if(my_strlen(cfg[i].cur.strval) > 0) {
          int g = 0;
          for(;cfg[i].cur.strval[g] != '\0';g++) {
            if(cfg[i].cur.strval[g] == '\n') {
              count++; 
              fprintf(stdout, "%c", cfg[i].cur.strval[g]);
              if((count % 20) == 0)
                bh_pager();
            } else if(g == 0)
              fprintf(stdout, "%c", cfg[i].cur.strval[g]);
            else
              fprintf(stdout, "%c", cfg[i].cur.strval[g]);
          }
        }
      }
      fprintf(stdout, "\n");
    } else if(cfg_sec == H) {
      fprintf(stdout, "%s\n", menu);
    } else if(my_strlen(ibuf) == 0) {
      /* Ignore NULL Input */
    } else {
      fprintf(stdout, "Bad Command -- %s!!!\n\n", ibuf);
    }

    /* prompt */
    fprintf(stdout, "%s> ", progname);
  }
}

void bh_pager(void) {
  int c;

  fprintf(stdout, "\n<Press Enter for more>");
  while((c = fgetc(stdin)) != '\n');
}

/* page and also check for input options */
char bh_pager_in(int flag) {
  int c, i, jx;
  char *obuf = NULL;
  int y = 0;
  int mode = -1;
  char *odata = NULL;

  strsize = 255;
  obuf = malloc(strsize + 1);
  if(obuf == NULL)
    exit(1);
  odata = malloc(MAX_CONFIG_LINE + 1);
  if(odata == NULL)
    exit(1);

  /* Prompt */
  if(flag == 0)
    fprintf(stdout, "\n<Press Enter to Scroll>\nOption Number> ");
  else
    fprintf(stdout, "\nOption Number> ");

  while(((c = fgetc(stdin)) != '\n') && y < strsize)
    obuf[y++] = c;
  obuf[y] = '\0';

  /* Premature exit or list basic options */
  if(obuf[0] == 'q')
    return 'q';
  else if(obuf[0] == 'l') {
    list_op();
    fprintf(stdout, "\n<Press Enter to Continue>");
    while((c = fgetc(stdin)) != '\n');
    y = 0;
  }

  if(y > 0) {
    /* Current Settings */
    if(my_strlen(cfg[atoi(obuf)-1].cur.strval) > 0) {
      int g = 0;
      int ix = atoi(obuf)-1;
      int count = 0;

      fprintf(stdout, " Current Value(s):\n  ");
      for(;cfg[ix].cur.strval[g] != '\0';g++) {
        if(cfg[ix].cur.strval[g] == '\n') {
          fprintf(stdout, "%c  ", cfg[ix].cur.strval[g]);
          count++; 
          if((count % 20) == 0 && count > 0)
            bh_pager();
        } else if(g == 0)
          fprintf(stdout, "%c", cfg[ix].cur.strval[g]);
        else
          fprintf(stdout, "%c", cfg[ix].cur.strval[g]);
      }
    }

    /* ask for config option (add/delete) */
    fprintf(stdout, "\n[add|delete|quit] {option}\nconfig> "); 
    while((c = fgetc(stdin))) {
      if(mode == -1 && (char)c == 'd')
        mode = 1;
      else if(mode == -1 && (char)c == 'a')
        mode = 0;
      else if(mode == -1 && (char)c == 'q') {
        fprintf(stdout, "\n");
        odata[0] = '\0';
        return '\0';
      } else if(mode != -1)
        break;
      else if(c == '\n') 
        fprintf(stdout, "[add|delete|quit] {option}\nconfig> "); 
    }

    /* skip rest of first arg */
    if((char)c != '\0' && (char)c != '\n') {
      while((c = fgetc(stdin)) != '\0' && 
           ((c = fgetc(stdin)) != '\n') && (char)c != ' ');
    }
  
    /* print section configuring */
    if(cfg[atoi(obuf)-1].section != NULL) {
      if(mode == 0)
        fprintf(stdout, "Adding to option [%s]:\n", cfg[atoi(obuf)-1].section);
      else if(mode != -1)
        fprintf(stdout, 
             "Deleting from option [%s]\n", cfg[atoi(obuf)-1].section);
    }

    /* print prompt if interactive */
    if((char)c != ' ') {
      if(mode == 0)
        fprintf(stdout, "\nconfig add> ");
      else
        fprintf(stdout, "\nconfig delete> ");
    }

    /* Get data and calculate which action, and run bhedit */
    while((fgets(odata, MAX_CONFIG_LINE + 1, stdin)) != NULL)
      break;

    /* clean input */
    if(odata[0] == ' ') {
      for(i = 0;odata[i] == ' ';i++);
      for(jx = 0; odata[i] != '\0';jx++,i++)
        odata[jx] = odata[i];
      odata[jx] = '\0';
    }
    for(i = 0; odata[i] != '\n' && odata[i] != '\0'; i++);
    odata[i] = '\0';
    if(odata[i-1] == ' ') {
      i--;
      while(odata[i--] == ' ');
      odata[i] = '\0';
    }
    /* Make simple a 1 or -1 for binary data */
    if(strcmp(odata,"0") == 0)
      strcpy(odata, "-1");
    else if(strcmp(odata,"on") == 0)
      strcpy(odata, "1");
    else if(strcmp(odata,"off") == 0)
      strcpy(odata, "-1");
    else if(strcmp(odata,"false") == 0)
      strcpy(odata, "-1");
    else if(strcmp(odata,"true") == 0)
      strcpy(odata, "1");
    else if(strcmp(odata,"no") == 0)
      strcpy(odata, "-1");
    else if(strcmp(odata,"yes") == 0)
      strcpy(odata, "1");

    if(my_strlen(odata) > 0) {
      if(mode == 1)
        bhedit("delete", cfg[atoi(obuf)-1].section, odata);
      else if(mode == 0)
        bhedit("add", cfg[atoi(obuf)-1].section, odata);
    } else
      return '\0';

    return 'X';
  }
  return '\0';
}
 
/* bhedit execution */
int bhedit(char *action, char *section, char *data) 
{
  int pid, status;
  char *bhedit = BH_EDIT_PROG;

  if(DEBUG)
    fprintf(stdout, "Running '%s %s %s %s %s'\n", 
         perl_bin, bhedit, action, section, data);
  else
    fprintf(stdout, "\n");

  pid = fork();
  if(pid == -1) {
    fprintf(stderr,
          "%s: Error Spawning Pid! %s:%d\n", __FILE__, __FILE__, __LINE__);
    return 1;
  }
  if(pid == 0) {
    char *bhedit_args[] = {
      bhedit,
      bhedit,
      "-f",
      config_file,
      action,
      section,
      data,
      '\0'
    };

    /* Run bhedit */
    execv(perl_bin, bhedit_args);

    /* Error if still here */
    fprintf(stderr, "Error Running bhedit\n");
    exit(127);
  }
  do {
    if(waitpid(pid, &status, 0) == -1) {
      if(errno != EINTR) {
        fprintf(stderr, "%s: Error Executing bhedit! %s:%d\n",
                __FILE__, __FILE__, __LINE__);
        return -1;
      }
    } else {
      status >>= 8;
      status &= 0xFF;

      if(status != 0) {
        fprintf(stderr, "Error with bhedit (%d)\n", status);
        return 1;
      } else {
        /* Read new config settings into BlackHole */
        readconfig(RC_USER);
        break;
      }
    }
  } while(1);

  return 0;
}

void list_op(void) {
  int i;

  for(i = 0; cfg[i].section != NULL; i++) {
    fprintf(stdout, " %02d) %-30s", i+1, cfg[i].section);
    if(((i+1) % 2) == 0)
      fprintf(stdout, "\n");
    else  
      fprintf(stdout, " ");
  }
}

void cfgmenu(void) 
{
  int count = 1, i, j;

  fprintf(stdout, "Config Options:\n");
  for(i = 0; cfg[i].section != NULL; i++) {
    char *wbuf = NULL;
    int x = 0;
    int f = 0;
    fprintf(stdout, " %02d) [%s] ", i+1, cfg[i].section);
    strsize = my_strlen(cfg[i].info);
    wbuf = malloc(strsize + 1);
    if(wbuf == NULL)
      exit(1);
    wbuf[strsize] = '\0';
    for(j=0;x < strsize && cfg[i].info[j] != '\0';j++) {
      if(cfg[i].info[j] != '\n') {
        wbuf[x++] = cfg[i].info[j];
        wbuf[x] = '\0';
      } else
        continue;
      if(isspace(cfg[i].info[j]) != 0 || cfg[i].info[j+1] == '\0') {
        if(((x % 45) == 0) && x > 0) {
          x = 0;
          f = 0;
          count++;
          fprintf(stdout, "%s\n      ", wbuf);
          if((count % 20) == 0 && count > 0)
            if(bh_pager_in(0) == 'q')
              return;
        } else if(x > 45 && f > 0) {
          x = 0;
          f = 1;
          count++;
          fprintf(stdout, "\n      %s", wbuf);
          if((count % 20) == 0 && count > 0)
            if(bh_pager_in(0) == 'q')
              return;
        } else if(x > 45) {
          f = 1;
          x = 0;
          fprintf(stdout, "%s", wbuf);
        }  
      }
    }
    if(x > 0 && wbuf != NULL && my_strlen(wbuf) > 0) {
      x = 0;
      if(f > 0) {
        count++;
        fprintf(stdout, "\n      %s", wbuf);
        if((count % 20) == 0 && count > 0)
          if(bh_pager_in(0) == 'q')
            return;
      } else
        fprintf(stdout, "%s", wbuf);
    }
    count++;
    fprintf(stdout, "\n");
    if((count % 20) == 0)
      if(bh_pager_in(0) == 'q')
        return;
    /* Page or Space */
    count++;
    if((count % 20) == 0) {
      if(bh_pager_in(0) == 'q')
        return;
    } else
      fprintf(stdout, "\n");
  }
}

