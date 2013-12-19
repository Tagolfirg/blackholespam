/* qmail-qfilter.c */
static char *id = 
     "$Id: qmail-qfilter.c,v 1.11 2002/08/08 20:08:07 bitbytebit Exp $";
/* Copyright (C) 2000 Bruce Guenter <bruceg@em.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#ifndef USE_MCONFIG

#include "config.h"
#endif
#if QFILTER == 1
#define QMAIL_QFILTER 1
#endif

#ifdef QMAIL_QFILTER

extern int envpipe[2];

#ifndef BUFSIZE
#define BUFSIZE 4096
#endif

#ifndef QMAIL_QUEUE_BIN
#define QMAIL_QUEUE_BIN "/var/qmail/bin/qmail-queue-old"
#endif

#define QQ_OOM 51
#define QQ_WRITE_ERROR 53
#define QQ_INTERNAL 81
#define QQ_BAD_ENV 91

#define QQ_DROP_MSG 99

/* remap the appropriate FDs and exec qmail-queue */
int run_qmail_queue(int tmpfd, int envpipe[2])
{
  if(close(envpipe[1]) == -1 ||
     dup2(tmpfd, 0) != 0 || close(tmpfd) == -1 ||
     dup2(envpipe[0], 1) != 1 || close(envpipe[0]) == -1)
    return QQ_WRITE_ERROR;
  execl(QMAIL_QUEUE_BIN, QMAIL_QUEUE_BIN, 0);
  return QQ_INTERNAL;
}

typedef int bool;
const bool false = 0;
const bool true = 0 == 0;

/* a replacement for setenv(3) for systems that don't have one */
bool mysetenv(const char* key, const char* val, size_t vallen)
{
  char* tmp;
  size_t keylen;
  
  keylen = strlen(key);
  tmp = malloc(keylen + 1 + vallen + 1);
  memcpy(tmp, key, keylen);
  tmp[keylen] = '=';
  memcpy(tmp+keylen+1, val, vallen);
  tmp[keylen+1+vallen] = 0;
  return putenv(tmp) != -1;
}

static const char* env = 0;
static size_t env_len = 0;

/* Parse the sender address into user and host portions */
int parse_sender(void)
{
  const char* ptr = env;
  char* at;
  size_t len = strlen(ptr);
  
  if(*ptr != 'F')
    return 0;
  ++ptr;
  
  /* This may be non-portable, and I don't know why it's needed */
  //unsetenv("QMAILNAME");
  
  if(!*ptr)
    return (putenv("QMAILUSER=") != -1 && putenv("QMAILHOST=") != -1) ?  2 : 0;

  at = strrchr(ptr, '@');
  if(!at) {
    len = strlen(ptr);
    if(!mysetenv("QMAILUSER", ptr, len) ||
       putenv("QMAILHOST=") == -1)
      return 0;
  }
  else {
    len = strlen(at);
    if(!mysetenv("QMAILUSER", ptr, at-ptr) ||
       !mysetenv("QMAILHOST", at+1, len-1))
      return 0;
    len += at-env;
  }
  return len + 1;
}

bool parse_rcpts(int offset)
{
  size_t len = env_len - offset;
  const char* ptr = env + offset;
  char* buf = malloc(len);
  char* tmp = buf;
  bool result;
  while(ptr < env + env_len && *ptr == 'T') {
    size_t rcptlen = strlen(++ptr);
    memcpy(tmp, ptr, rcptlen);
    tmp[rcptlen] = '\n';
    tmp += rcptlen + 1;
    ptr += rcptlen + 1;
  }
  result = mysetenv("QMAILRCPTS", buf, tmp-buf);
  return result;
}

bool parse_envelope(void)
{
  int rcpts = parse_sender();
  if(!rcpts)
    return false;
  return parse_rcpts(rcpts);
}

struct bufchain
{
  size_t len;
  char* buf;
  struct bufchain* next;
};
typedef struct bufchain bufchain;

/* Read the envelope from FD 1, and parse the sender address */
bool read_envelope()
{
  bufchain* head = 0;
  bufchain* tail = 0;
  char* ptr;
  
  for(;;) {
    char buf[BUFSIZE];
    bufchain* newbuf;
    ssize_t rd;

    rd = read(1, buf, BUFSIZE);
    if(rd == -1)
      return false;
    if(rd == 0)
      break;
    newbuf = malloc(sizeof(bufchain));
    newbuf->len = rd;
    newbuf->buf = malloc(rd);
    memcpy(newbuf->buf, buf, rd);
    if(tail)
      tail->next = newbuf;
    else
      head = newbuf;
    tail = newbuf;
    env_len += rd;
  }
  if (!tail) return false;
  tail->next = 0;

  /* copy the buffer chain into a single buffer */
  ptr = malloc(env_len);
  env = ptr;
  while(head) {
    bufchain* next = head->next;
    memcpy(ptr, head->buf, head->len);
    ptr += head->len;
    free(head->buf);
    free(head);
    head = next;
  }
  
  return parse_envelope();
}

/* Write out the envelope to a pipe */
int write_envelope(int envpipe[2])
{
  if(close(envpipe[0]) == -1)
    return 1;
  /* Funny logic here to catch short writes */
  while(env_len > 0) {
    ssize_t w = write(envpipe[1], env, env_len);
    if(w == -1)
      return 1;
    env += w;
    env_len -= w;
  }
  if(close(envpipe[1]) == -1)
    return 1;
  return 0;
}


/* Create a temporary invisible file opened for read/write */
int mktmpfile(char *filename)
{
  int fd = open(filename, O_RDWR, 0600);
  if(fd == -1)
    return -1;

  /* The following makes the temporary file disappear immediately on
     program exit. */
  if(unlink(filename) == -1)
    return -1;

  /* Seek to beginning of file */
  if(lseek(fd, 0, SEEK_SET) != 0)
    return -1;

  return fd;
}

/* Wait for qmail-queue to exit, and return an error code */
int wait_qq(pid_t pid, int error)
{
  int status;
  if(waitpid(pid, &status, WUNTRACED) == -1)
    return QQ_INTERNAL;

  if(!WIFEXITED(status))
    error = QQ_INTERNAL;
  else if(WEXITSTATUS(status))
    error = WEXITSTATUS(status);
  
  return error;
}

int qfilter(char *file)
{
  if(file == NULL) {
    if(pipe(envpipe) == -1)
      return QQ_WRITE_ERROR;

    if(!read_envelope())
      return QQ_BAD_ENV;
  } else {
    int tmpfd;
    pid_t queue_pid;
    int error;
  
    tmpfd = mktmpfile(file);
    if(tmpfd < 0)
      return -QQ_WRITE_ERROR;

    queue_pid = fork();
    switch(queue_pid) {
    case 0:
      return run_qmail_queue((int) tmpfd, envpipe);
    case -1:
      return QQ_OOM;
    }

    error = write_envelope(envpipe) ? QQ_WRITE_ERROR : 0;
    return wait_qq(queue_pid, error);
  }
  return 0;
}
#endif
