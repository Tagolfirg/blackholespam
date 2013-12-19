/* mysqlconfig.c */
static char *id = 
     "$Id: sqlconfig.c,v 1.2 2002/08/24 08:21:56 bitbytebit Exp $";
/*
   Copyright (C) 2002
        Chris Kennedy, The Groovy Organization.
        Jakob Saternus contributed the Postfix code.

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
#if WITH_SQL == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#if WITH_PQSQL == 1
 #include <libpq-fe.h>
#else
 #include <mysql/mysql.h>
#endif
#include <time.h>
#include "my_string.h"
#include "max.h"
#include "misc.h"

extern int DEBUG;

int get_config_tstamp(char *);

extern char *username;
extern char *hostname;
extern char *homedir;
extern char *sql_user;
extern char *sql_pass;
extern char *sql_host;
extern char *sql_domain;
extern char *config_file;
extern char *spool_dir;
extern int qmail_queue;
extern int pfilter;

int sql_config(void)
{
  int i;
  int num_fields;
  char *fields[MAX_MYSQL_FIELDS+1];
#if WITH_PQSQL == 1
  PGconn *connection;
  PGresult *result;
#else
  MYSQL *connection;
  MYSQL mysql;
  MYSQL_RES *results = NULL;
  MYSQL_FIELD *field;
  MYSQL_ROW row;
#endif
  char *query_start = "SELECT * from BlackHole where username=";
  char *query_end = "and domain=";
  char *query_tstamp = "SELECT timestamp from BlackHole where username=";
  char *query;
  char *tquery;
  int loc_cfg_mtime;
  int rem_cfg_mtime;
  FILE *config_tmp = NULL;
  FILE *lck = NULL;
  char *sql_lfile = ".bh_sql";
  char *sql_lock;
  char *sql_lock_link;
  pid_t pid;
  time_t now;
  int f_strsize;

  /* get current UNIX time and PID */
  time(&now);
  pid = getpid();

  if(qmail_queue == 1 || pfilter == 1) {
    f_strsize = my_strlen(spool_dir) + my_strlen(sql_lfile) + 6;
    strsize = 
      my_strlen(spool_dir) + my_strlen(sql_lfile) + my_strlen(hostname) + 29;
  } else {
    f_strsize = my_strlen(sql_lfile) + my_strlen(homedir) + 1;
    strsize = 
      my_strlen(homedir) + my_strlen(sql_lfile) + my_strlen(hostname) + 24; 
  }

  sql_lock = malloc(f_strsize + 1);
  sql_lock_link = malloc(strsize + 1);
  if(bh_assert(sql_lock_link == NULL))
    return 1;

  if(qmail_queue == 1 || pfilter == 1) {
    snprintf(sql_lock, f_strsize + 1,
           "%s/conf/%s", 
	   spool_dir, sql_lfile);
    snprintf(sql_lock_link, strsize + 1,
           "%s/conf/%s.%d.%d.%s", 
	   spool_dir, sql_lfile, (int) now, pid, hostname);
  } else {
    snprintf(sql_lock, strsize + 1,
           "%s/%s", homedir, sql_lfile);
    snprintf(sql_lock_link, strsize + 1,
           "%s/%s.%d.%d.%s", homedir, sql_lfile, (int) now, pid, hostname);
  }
  sql_lock[f_strsize] = (char)'\0';
  sql_lock_link[strsize] = (char)'\0';

  lck = fopen(sql_lock_link, "w");
  if(bh_assert(lck == NULL))
    return 1;

  /* try linking lock file */
  if(link(sql_lock_link, sql_lock) != 0) {
    fclose(lck);
    unlink(sql_lock_link);
    return 1;
  } else
    fclose(lck);

#if WITH_PQSQL == 1
  connection = PQsetdbLogin(sql_host, "2345",
                       NULL, NULL, "BlackHole",
                       sql_user, sql_pass);

  if(PQstatus(connection) == CONNECTION_BAD) {
    fprintf(stderr, PQerrorMessage(connection));
    fprintf(stderr, "\n");
    PQfinish(connection);
    unlink(sql_lock);
    unlink(sql_lock_link);
    return 1;
  }
#else
  if(bh_assert(!mysql_init(&mysql))) {
    fprintf(stderr, "%s\n", mysql_error(&mysql));
    unlink(sql_lock);
    unlink(sql_lock_link);
    return 1;
  }

  connection = mysql_real_connect(&mysql,
                                  sql_host,
                                  sql_user, sql_pass,
                                  "BlackHole", 0, "", 0);

  if(bh_assert(connection == NULL)) {
    fprintf(stderr, "%s\n", mysql_error(&mysql));
    mysql_close(&mysql);
    unlink(sql_lock);
    unlink(sql_lock_link);
    return 1;
  }
#endif

  strsize = my_strlen(query_tstamp) + my_strlen(username) +
           my_strlen(query_end) + my_strlen(sql_domain) + 5;
  tquery = malloc(strsize + 1);
  if(bh_assert(tquery == NULL))
    goto exit_bad;
  snprintf(tquery, strsize + 1,
           "%s'%s' %s'%s'", query_tstamp, username, query_end, sql_domain);
  tquery[strsize] = (char)'\0';

#if WITH_PQSQL == 1
  /* Make PgSQL timestamp Query */
  results = PQexec(connection, tquery);
  if (results == NULL) {
    goto exit_bad;
  }
  if (PQresultStatus(results) != PGRES_TUPLES_OK)
    goto exit_bad;
#else
  /* Make MySQL timestamp Query */
  mysql_real_query(&mysql, tquery, my_strlen(tquery));
  results = mysql_use_result(&mysql);
  if(bh_assert(results == NULL)) {
    mysql_close(&mysql);
    unlink(sql_lock);
    unlink(sql_lock_link);
    return 1;
  }
  row = mysql_fetch_row(results);
  if(row == NULL)
    goto exit_bad;
#endif

  /* Get the array of lengths for each field */
#if WITH_PQSQL == 1
  num_fields = PQnfields(results);
#else
  num_fields = mysql_num_fields(results);
#endif
  i = 0;
#if WITH_PQSQL == 1
  while((field = PQfname(results,0)) != NULL) {
    if(strcmp(field, "timestamp") == 0) {
      rem_cfg_mtime = (int) atoi(PQgetvalue(result,i,0));
#else
  while((field = mysql_fetch_field(results)) != NULL) {
    if(strcmp(field->name, "timestamp") == 0) {
      rem_cfg_mtime = (int) atoi(row[i]);
#endif
      loc_cfg_mtime = get_config_tstamp(config_file);

      /* New sql entry, no timestamp yet */
      if(rem_cfg_mtime == 0) {
        goto exit_bad;
        /* local config is newer than sql, cached */
      } else if(rem_cfg_mtime <= loc_cfg_mtime) {
        goto exit_bad;
        /* remote sql config is newer than local */
      } else if(rem_cfg_mtime > loc_cfg_mtime) {
        /* Open tmp lock file */
        config_tmp = fopen(sql_lock_link, "w");
        if(config_tmp == NULL)
          goto exit_bad;

        if(DEBUG)
          fprintf(stderr, "Local Config last modified at: %d\n", loc_cfg_mtime);
        if(DEBUG)
          fprintf(stderr, "SQL Config last modified at: %d\n", rem_cfg_mtime);
        if(DEBUG)
          fprintf(stderr, "Local cache is stale, retrieving new config...\n");
        break;
      }
      goto exit_bad;
    }
    i++;
  }
#if WITH_PQSQL == 1
  PQclear(results);
#else
  mysql_free_result(results);
#endif

  strsize = (my_strlen(query_start) + my_strlen(username) +
           my_strlen(query_end) + my_strlen(sql_domain) + 5);
  query = malloc(strsize + 1);
  if(bh_assert(query == NULL))
    goto exit_bad;
  snprintf(query, strsize + 1, 
           "%s'%s' %s'%s'", query_start, username, query_end, sql_domain);
  query[strsize] = (char)'\0';

#if WITH_PQSQL == 1
  /* Make PgSQL Query */
  results = PQexec(connection, query);
  if(results == NULL)
    goto exit_bad;

  if(PQresultStatus(results) != PGRES_TUPLES_OK)
    goto exit_bad;

  num_fields = PQnfields(results);

  /* Walk through results */
  i = 0;
  while((field = PQfname(results,i)) != NULL) {
    /* Skip username, we know it already */
    if(strcmp(fields, "username") == 0) {
      i++;
      continue;
      /* Get timestamp */
    } else if(strcmp(fields, "timestamp") == 0) {
      i++;
      continue;
    } else if(strcmp(fields, "domain") == 0) {
      i++;
      continue;
    }

    /* The other fields */
    strsize = my_strlen(field);
    if(strsize > MAX_CONFIG_LINE)
      strsize = MAX_CONFIG_LINE;
    fields[i] = malloc(strsize + 1);
    if(fields[i] == NULL)
      goto exit_bad;
    
    my_strlcpy(fields[i], fields, strsize+1);
    fields[i][strsize] = (char)'\0';
#else
  /* Make MySQL Query */
  mysql_real_query(&mysql, query, strsize);
  results = mysql_use_result(&mysql);
  if(results == NULL)
    goto exit_bad;

  row = mysql_fetch_row(results);
  if(row == NULL)
    goto exit_bad;

  /* Get the array of lengths for each field */
  num_fields = mysql_num_fields(results);

  /* Walk through results */
  i = 0;
  while(i <= MAX_MYSQL_FIELDS && (field = mysql_fetch_field(results)) != NULL) {
    /* Skip username, we know it already */
    if(strcmp(field->name, "username") == 0) {
      i++;
      continue;
      /* Get timestamp */
    } else if(strcmp(field->name, "timestamp") == 0) {
      i++;
      continue;
    } else if(strcmp(field->name, "domain") == 0) {
      i++;
      continue;
    }

    /* The other fields */
    strsize = my_strlen(field->name);
    if(strsize > MAX_CONFIG_LINE)
      strsize = MAX_CONFIG_LINE;
    fields[i] = malloc(strsize + 1);
    if(fields[i] == NULL)
      goto exit_bad;
    
    my_strlcpy(fields[i], field->name, strsize+1);
    fields[i][strsize] = (char)'\0';
#endif

    /* Print out row field and value */
    if(row[i] != NULL) {
      fprintf(config_tmp, "[%s]\n", fields[i]);
      if(strcmp(row[i],"NULL") != 0)
        fprintf(config_tmp, "%s\n", row[i]);
    } else if(fields[i] != NULL) {
      fprintf(config_tmp, "[%s]\n", fields[i]);
    }

    i++;
  }

  /* Close tmp config file */
  fclose(config_tmp);

  /* Rename tmp file to config */
  if(rename(sql_lock_link, config_file) == -1) {
    fprintf(stderr, "The file %s is not rewritable by the blackhole process.\n",
	config_file);
    fprintf(stderr, "You may need to make this rewritable by qmailq or\n");
    fprintf(stderr, "whoever is running blackhole, exiting...\n");
    goto exit_bad;
  }
  goto exit_good;

exit_bad:
#if WITH_PQSQL == 1
  PQclear(results);
  PQfinish(connection);
#else
  mysql_free_result(results);
  mysql_close(&mysql);
#endif
  unlink(sql_lock);
  unlink(sql_lock_link);
  return 1;

exit_good:
#if WITH_PQSQL == 1
  PQclear(results);
  PQfinish(connection);
#else
  mysql_free_result(results);
  mysql_close(&mysql);
#endif
  unlink(sql_lock);
  unlink(sql_lock_link);
  return 0;
}

int get_config_tstamp(char *filename)
{
  struct stat buf;

  if(stat(filename, &buf) == 0) {
    if(buf.st_mtime != 0)
      return buf.st_mtime;
  }
  return -1;
}
#endif
