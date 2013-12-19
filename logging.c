/* logging.c */
static char *id = 
     "$Id: logging.c,v 1.23 2003/01/07 15:16:05 bitbytebit Exp $";
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
#include <sys/syslog.h>
#include "my_string.h"
#include "max.h"

#ifndef USE_MCONFIG
#include "config.h"
#endif

#if WITH_SQL == 1
#if WITH_PQSQL == 1
#else
#include <mysql/mysql.h>
#endif
int bh_sqllog(char *);
#endif

int bh_syslog(char *);

int bh_stderr(char *);
int bh_stdout(char *);

extern char *username;
extern char *timestamp;
extern char *hostname;

#if WITH_SQL == 1
extern char *sql_user;
extern char *sql_pass;
extern char *sql_host;
extern char *sql_domain;
#endif

extern int log_type;
enum log_types
{
  error = 0,
  output,
  syslg,
  sql
};

extern float score;
extern int msg_size;
extern char *iprelay;
extern char *mailfrom;
extern char *rcptto;

extern int log_score;
extern int log_size;
extern int log_iprelay;
extern int log_sender;
extern int log_recipient;

int logging(char *line)
{
  enum log_types ltype = log_type;
  char *logbuffer = NULL;
  char *msg_size_p = "", *score_p = "";
  char *iprelay_p = "", *mailfrom_p = "", *rcptto_p = "";

  /* Clean up NULL variables */
  if(username == NULL) {
    username = malloc(7);
    if(username == NULL)
      return 1;
    strcpy(username, "NOUSER");
  }
  if(hostname == NULL) {
    hostname = malloc(7);
    if(hostname == NULL)
      return 1;
    strcpy(hostname, "NOHOST");
  }
  if(timestamp == NULL) {
    timestamp = malloc(7);
    if(timestamp == NULL)
      return 1;
    strcpy(timestamp, "NOTIME");
  }

  /* Check for extra things to log */
  /* score, msg_size, iprelay, mailfrom, rcptto */
    if(log_score == 1 || log_size == 1 || log_iprelay == 1 || log_sender == 1 ||
         log_recipient == 1) {
      /* Size */
      if(msg_size > 0 && log_size == 1) {
        strsize = typlen(int) + 7;
        msg_size_p = malloc(strsize + 1);
        if(msg_size_p == NULL)
          return 1;
        snprintf(msg_size_p, strsize + 1, "size: %d ", msg_size); 
      }
      /* Score */
      if(score > 0 && log_score == 1) {
        strsize = typlen(float)+2 + 8;
        score_p = malloc(strsize + 1);
        if(score_p == NULL)
          return 1;
        snprintf(score_p, strsize + 1, "score: %.2f ", score); 
      }
      /* Relay */
      if(iprelay != NULL && my_strlen(iprelay) > 0 && log_iprelay == 1) {
        strsize = my_strlen(iprelay) + 8;
        iprelay_p = malloc(strsize + 1);
        if(iprelay_p == NULL)
          return 1;
        snprintf(iprelay_p, strsize + 1, "relay: %s ", iprelay); 
      }
      /* Sender */
      if(mailfrom != NULL && my_strlen(mailfrom) > 0 && log_sender == 1) {
        strsize = my_strlen(mailfrom) + 7;
        mailfrom_p = malloc(strsize + 1);
        if(mailfrom_p == NULL)
          return 1;
        snprintf(mailfrom_p, strsize + 1, "from: %s ", mailfrom); 
      }
      /* Recipient */
      if(rcptto != NULL && my_strlen(rcptto) > 0 && log_recipient == 1) {
        strsize = my_strlen(rcptto) + 8;
        rcptto_p = malloc(strsize + 1);
        if(rcptto_p == NULL)
          return 1;
        snprintf(rcptto_p, strsize + 1, "to: %s ", rcptto); 
      }

      /* Create Log Line */
      strsize = my_strlen(line) + my_strlen(msg_size_p) + my_strlen(score_p) 
           + my_strlen(iprelay_p) + my_strlen(mailfrom_p) + my_strlen(rcptto_p)
           + 4;
      logbuffer = malloc(strsize + 1);
      if(logbuffer == NULL)
        return 1;
      snprintf(logbuffer, strsize + 1, 
           "[ %s%s%s%s%s] %s", 
           msg_size_p, score_p, iprelay_p, mailfrom_p, rcptto_p, line);
    } else
      logbuffer = line; 

#if WITH_SQL == 1
  if(ltype == sql)
    bh_sqllog(logbuffer);
  else if(ltype == syslg)
#else
  if(ltype == syslg)
#endif
    bh_syslog(logbuffer);
  else if(ltype == output)
    bh_stdout(logbuffer);
  else
    bh_stderr(logbuffer);

  return 0;
}

int bh_syslog(char *line)
{
  char *logbuf;
  openlog("BlackHole", 0, LOG_MAIL);
  strsize = my_strlen(username) + my_strlen(line) + 1;
  if(strsize > 1023)
    strsize = 1023;
  logbuf = malloc(strsize+1);
  if(logbuf == NULL)
    return 0;
  snprintf(logbuf,strsize+1,"%s %s",username,line);
  logbuf[strsize] = (char)'\0';
  syslog(LOG_INFO, "%s", logbuf);
  closelog();

  return 0;
}

#if WITH_SQL == 1
/* table format:  timestamp, username, domain, entry */
int bh_sqllog(char *line)
{
#if WITH_PQSQL == 1
#else
  MYSQL *connection;
  MYSQL mysql;
  MYSQL_RES *results;
#endif
  char *query_start = "INSERT into log set username='";
  char *query_two = "',domain='";
  char *query_three = "',hostname='";
  char *query_four = "',status='";
  char *query_five = "',score='";
  char *query_six = "',size='";
  char *query_seven = "',relay='";
  char *query_eight = "',sender='";
  char *query_nine = "',recipient='";
  char *query;
  char *status="UNKNOWN";
  char *score="0";
  char *size="0";
  char *relay="";
  char *sender="";
  char *recipient=""; 
  char *scratch;
  char *pos;

#if WITH_PQSQL == 1
#else
  if(!mysql_init(&mysql)) {
    fprintf(stderr, "%s\n", mysql_error(&mysql));
    return 1;
  }

  connection = mysql_real_connect(&mysql,
                                  sql_host,
                                  sql_user, sql_pass,
                                  "BlackHole", 0, "", 0);

  if(connection == NULL) {
    fprintf(stderr, "%s\n", mysql_error(&mysql));
    mysql_close(&mysql);
    return 1;
  }
#endif

  // When other logging options are enabled they are surrounded by []
  if(index(line,']')) {
	scratch=(char *)malloc(my_strlen(line));
	if(pos=strstr(line,"] ")) {
		status=pos+2;  // Status is 2 chars after the ']'
	}
	if(pos=strstr(line,"score: ")) {
		sscanf(pos, "score: %s",scratch);
		score=(char *)malloc(my_strlen(scratch)+1);
		my_strlcpy(score,scratch,my_strlen(scratch)+1);
	}
	if(pos=strstr(line,"size: ")) {
		sscanf(pos,"size: %s",scratch);
		size=(char *)malloc(my_strlen(scratch)+1);
		my_strlcpy(size,scratch,my_strlen(scratch)+1);
	}
	if(pos=strstr(line,"relay: ")) {
		sscanf(pos,"relay: %s",scratch);
		relay=(char *)malloc(my_strlen(scratch)+1);
		my_strlcpy(relay,scratch,my_strlen(scratch)+1);
	}
	if(pos=strstr(line,"from: ")) {
		sscanf(pos,"from: %s",scratch);
		sender=(char *)malloc(my_strlen(scratch)+1);
		my_strlcpy(sender,scratch,my_strlen(scratch)+1);
	}
	if(pos=strstr(line,"to: ")) {
		sscanf(pos,"to: %s",scratch);
		recipient=(char *)malloc(my_strlen(scratch)+1);
		my_strlcpy(recipient,scratch,my_strlen(scratch)+1);
	}
	free(scratch);
  } else {  // No additional logging options were set
	status=line;
  }

  strsize = my_strlen(query_start) + my_strlen(username) + 
	my_strlen(query_two) + my_strlen(sql_domain) + 
	my_strlen(query_three) + my_strlen(hostname) + my_strlen(query_four) + 
	my_strlen(status) + my_strlen(query_five) + my_strlen(score) +
	my_strlen(query_six) + my_strlen(size) + my_strlen(query_seven) +
	my_strlen(relay) + my_strlen(query_eight) + my_strlen(sender) +
	my_strlen(query_nine) + my_strlen(recipient) + 1;

  query = malloc(strsize + 1);
  snprintf(query, strsize + 1,  "%s%s%s%s"
		  		"%s%s%s%s"
				"%s%s%s%s"
				"%s%s%s%s"
				"%s%s'", 
	query_start, username, query_two, sql_domain, 
	query_three, hostname, query_four, status,
	query_five, score, query_six, size,
	query_seven, relay, query_eight, sender,
	query_nine, recipient);
  query[strsize] = (char)'\0';

#if WITH_PQSQL == 1
#else
  mysql_real_query(&mysql, query, my_strlen(query));
  results = mysql_use_result(&mysql);
  if(results > 0) {
#if WITH_DEBUG == 1
	  fprintf(stderr,"SQLLOG failed: (%s)\nError: %s\n",query,mysql_error(&mysql));
#endif
    return 1;
  }

  mysql_free_result(results);
  mysql_close(&mysql);
#endif

  return 0;
}
#endif

int bh_stdout(char *line)
{
  fprintf(stdout, "%s %s %s %s\n", timestamp, hostname, username, line);

  return 0;
}

int bh_stderr(char *line)
{
  fprintf(stderr, "%s %s %s %s\n", timestamp, hostname, username, line);

  return 0;
}
