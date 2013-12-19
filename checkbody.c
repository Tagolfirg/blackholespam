/* checkbody.c */
static char *id = 
     "$Id: checkbody.c,v 1.37 2002/08/29 16:33:51 bitbytebit Exp $";
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
#if HAVE_LIBPCRE == 1

#include <stdio.h>
#include <string.h>
#include <pcre.h>
#include <stdlib.h>
#include "body_patterns.h"
#include "max.h"
#include "my_string.h"

int check_line(char *, char *);

extern int DEBUG;
extern int SPAM_BODY;
extern int PORN_BODY;
extern int RACIST_BODY;
extern int MY_BODY;
extern float my_score, spam_score, porn_score, racist_score;
extern float my_thresh, spam_thresh, porn_thresh, racist_thresh;
extern char *log_info;

extern char *mybody[];

#define OVECCOUNT 30            /* multiple of 3 */

int check_body(char *line)
{
  int i, t;
  float cust_score;
  char *cust_line;

  /* Body checking categories */
  if(MY_BODY > 0) {
    if(MY_BODY > 1)
      my_thresh = MY_BODY;
    cust_line = malloc(MAX_CONFIG_LINE + 1);
    if(cust_line == NULL)
      return 0;
    for(i = 0; mybody[i] != NULL; i++) {
      if((t = sscanf(mybody[i], "%f: %[^\n]", &cust_score, cust_line)) != 2) {
        cust_score = 1.0;
        strsize = my_strlen(mybody[i]);
        my_strlcpy(cust_line, mybody[i], strsize+1);
      }
      if(check_line(cust_line, line)) {
        /* Match My Custom pattern */
#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, " Custom Line: %s", line);
#endif
        my_score += cust_score;
        if(my_score >= my_thresh) {
          strsize = (typlen(float)+3 + my_strlen(mybody[i]) + 9);
          log_info = malloc(strsize + 1);
          if(log_info == NULL)
            return 0;

          snprintf(log_info, strsize+1, "(score %.2f) %s", my_score, mybody[i]);
          log_info[strsize] = (char)'\0';

          if(DEBUG)
            fprintf(stderr, " Match Custom Body %s\n", log_info);

          free(cust_line);
          return MY;
        }
      }
    }
    free(cust_line);
  }
  if(SPAM_BODY > 0) {
    if(SPAM_BODY > 1)
      spam_thresh = SPAM_BODY;
    for(i = 0; spam_pattern[i].pattern != NULL; i++) {
      if(check_line(spam_pattern[i].pattern, line)) {
        /* Match Spam */
#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, " Spam Line: %s", line);
#endif
        spam_score += spam_pattern[i].score;
        if(spam_score >= spam_thresh) {
          strsize = (typlen(float)+3 + my_strlen(spam_pattern[i].pattern) + 9);
          log_info = malloc(strsize + 1);
          if(log_info == NULL)
            return 0;

          snprintf(log_info, strsize + 1, 
		   "(score %.2f) %s", spam_score, spam_pattern[i].pattern);
          log_info[strsize] = (char)'\0';

          if(DEBUG)
            fprintf(stderr, " Match Spam Body %s\n", log_info);

          return SPAM;
        }
      }
    }
  }
  if(PORN_BODY > 0) {
    if(PORN_BODY > 1)
      porn_thresh = PORN_BODY;
    for(i = 0; porn_pattern[i].pattern != NULL; i++) {
      if(check_line(porn_pattern[i].pattern, line)) {
        /* Match Porn */
#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, " Porn Line: %s", line);
#endif
        porn_score += porn_pattern[i].score;
        if(porn_score >= porn_thresh) {
          strsize = typlen(float)+3 + my_strlen(porn_pattern[i].pattern) + 9;
          log_info = malloc(strsize + 1);
          if(log_info == NULL)
            return 0;

          snprintf(log_info, strsize + 1,
                   "(score %.2f) %s", porn_score, porn_pattern[i].pattern);

          if(DEBUG)
            fprintf(stderr, " Match Body Porn %s\n", log_info);

          return PORN;
        }
      }
    }
  }
  if(RACIST_BODY > 0) {
    if(RACIST_BODY > 1)
      racist_thresh = RACIST_BODY;
    for(i = 0; racist_pattern[i].pattern != NULL; i++) {
      if(check_line(racist_pattern[i].pattern, line)) {
        /* Match Racist */
#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, " Racist Line: %s", line);
#endif
        racist_score += racist_pattern[i].score;
        if(racist_score >= racist_thresh) {
          strsize = typlen(float)+3 + my_strlen(racist_pattern[i].pattern) + 9;
          log_info = malloc(strsize + 1);
          if(log_info == NULL)
            return 0;

          snprintf(log_info, strsize + 1,
                   "(score %.2f) %s", racist_score, racist_pattern[i].pattern);

          if(DEBUG)
            fprintf(stderr, " Match Racist Body %s\n", log_info);

          return RACIST;
        }
      }
    }
  }

  /* No Match after all patterns checked against threshholds */
  return 0;
}

int check_line(char *pattern, char *line)
{
  pcre *re;
  const char *error;
  int erroffset;
  int ovector[OVECCOUNT];
  int rc;

  re = pcre_compile(pattern, 0, &error, &erroffset, NULL);
  if(re == NULL)
    return 0;
  rc = pcre_exec(re,
            NULL, line, (int) my_strlen(line), 0, 0, ovector, OVECCOUNT);
  pcre_free(re);

  /* Check return value */
  if(rc < 0) {
    switch (rc) {
    case PCRE_ERROR_NOMATCH:
      break;
    default:
      if(DEBUG)
        fprintf(stderr, "Matching Error %d\n", rc);
      break;
    }
    /* No Match */
    return 0;
  }

  /* Match */
  return 1;
}
#endif
