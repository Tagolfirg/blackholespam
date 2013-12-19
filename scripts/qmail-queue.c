#include <stdio.h>

#include "../config.h"

#ifndef QPROGRAM
#define QPROGRAM "/opt/blackhole/bin/blackhole"
#endif

#ifndef QSPOOL_DIR
#define QSPOOL_DIR "/var/spool/blackhole/msg"
#endif

extern char **environ;

int main(int argc, char *argv[]) {
  char *qmail_qfilter = "/var/qmail/bin/qmail-qfilter";
  char *args[] = {
		qmail_qfilter,
		QPROGRAM,
		"-Q",
		"-m",
		QSPOOL_DIR,
		'\0'
  };

  /* Execute it */
  execve(qmail_qfilter,args,environ);
  fprintf(stderr,"ERROR, you need to modify the paths in scripts/qmail-queue.c\n");
  fprintf(stderr,"and reinstall it, by default they are /opt/blackhole/bin/blackhole\n");
  fprintf(stderr,"for the blackhole executable and /var/spool/blackhole/msg for\n");
  fprintf(stderr,"the maildir storage of blocked email in this mode.\n\n");
  return 1; /* didn't run */
}
