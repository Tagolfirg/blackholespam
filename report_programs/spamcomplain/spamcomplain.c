/* 	$Id: spamcomplain.c,v 1.5 2002/10/08 20:01:54 bitbytebit Exp $	 */

#ifndef lint
static char vcid[] = "$Id: spamcomplain.c,v 1.5 2002/10/08 20:01:54 bitbytebit Exp $";
#endif /* lint */

/* Automated complaint generator for spam mail.
   Copyright (C) 2002
   David Ronis

This file is part of spamcomplain.

spamcomplain is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

spamcomplain is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with spamcomplain; see the file COPYING.  If not, write to the
Free Software Foundation, 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <regex.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <fcntl.h>
#include <termios.h>
#include <limits.h>
#include <glob.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/utsname.h>

/*  Various Definitions; Change to suit your site */

#define DO_DSBL        /* Turn on relay testing, with reporting to
			  dsbl lists.  You have to have the test-dsbl
			  programs installed (see below).  */

#undef DO_RBL          /* Turns on code that sends e-mail to RBL site
			  managers.  This currently doesn't work,
			  since the RBL sites don't look for entries
			  this way.  DON'T CHANGE THIS. */

#ifndef BUFMAX 
#define BUFMAX 4098  /* Size for various buffers used to read in lines
			of e-mail.  Reads are typically done with
			fgets, so overflow won't be an issue.
			*/
#endif /* BUFMAX */

#ifndef MAXLOG 
#define MAXLOG 800    /* Maximum number of characters from message to
			  keep in the log */
#endif /* MAXLOG */

#ifndef DEFAULT_PATH 

/* Default path for logs, messages etc. It is used only if the HOME
   environment variable isn't defined or if there is not
   DEFAULT_DIRECTORY in the current directory. */

#define DEFAULT_PATH ".spamcomplain"
#endif /* DEFAULT_PATH */

#ifndef DEFAULT_DIRECTORY 

/* Where exlusion files, logs, complaint messages go.  This is
   expected to be found in the $HOME directory.  */

#define DEFAULT_DIRECTORY ".spamcomplain" 
#endif /* DEFAULT_DIRECTORY */

#ifndef DEFAULT_EXCLUDE 
#define DEFAULT_EXCLUDE "excludes"    /* Default exclusions file */
#endif /* DEFAULT_EXCLUDE */

#ifndef DEFAULT_LOG 
#define DEFAULT_LOG     "log"         /* Default log file */
#endif /* DEFAULT_LOG */

#ifndef SPAMMERS_LIST
#define SPAMMERS_LIST "spammers"      /* File containing List of
					 spammers created with -S & -r
					 flags. */
#endif /*SPAMMERS_LIST*/

#ifndef INDENTSTRING 
#define INDENTSTRING  "\n>     "        /* String for including email */
#endif /* INDENTSTRING */


#ifndef MAXEXCLUDE 
#define MAXEXCLUDE  1024    /* Largest number of exclusions allowed */
#endif /* MAXEXCLUDE */

#ifndef MAXLOGHOSTS 
#define MAXLOGHOSTS 1024    /* Largest number of different log entries */
#endif /* MAXLOGHOSTS */

#ifndef MAXWHOIS 
#define MAXWHOIS    256     /* Maximum number of whois complaints */
#endif /* MAXWHOIS */

#ifndef MAXBADEMAILS
#define MAXBADEMAILS 1024   /* Maximum number of bad emails per session */
#endif /*MAXBADEMAILS*/

#ifndef WHOISDEPTH 
#define WHOISDEPTH  4       /* Depth for whois lookups */
#endif /* WHOISDEPTH */

#ifndef WHOISPATH
#define WHOISPATH    "/usr/local/bin"  /* The whois program path */
#endif /*WHOISPATH*/

#define SLEEPTIME  300     /* Time to sleep between checking if
			      subprocess has terminated.  Subproceses
			      that don't complete are presumed to have
			      hung and are killed. */

#ifndef WHOISPROGRAM 
#define WHOISPROGRAM "jwhois"  /* The whois program wrapper.  I used the gnu
				  whois client, since it handles
				  regional redirection automatically.
				  You can find it at gnu.org.  */
#endif /* WHOISPROGRAM */

 /* Pattern to find references to national whois services. This isn't
    really necessary if jwhois is used, but included for olderwhois
    clients.  */

static char *whoispattern="whois[ \t]+-h[ \t]+[^ \t\n]+"; 

/* Patterns to exclude from whois response */

static char *whoisexcludepattern="changed|source";

/* default_spam_message is the default message sent to complain about
   spam.  */

#ifdef DO_DSBL
#ifndef DSBL_TEST_PROGRAM
#define DSBL_TEST_PROGRAM "/usr/local/bin/spamtrap"  /* See
							http://dsbl.org
							for links to
							this
							program. */
#endif /*DSBL_TEST_PROGRAM*/
#endif /*DO_DSBL*/

static char *default_spam_message=
"\n\n----THIS IS AN AUTOMATICALLY GENERATED EMAIL----\n\n\
Hello, recently I received the attached unsolicited e-mail.  I am\n\
forwarding it to you because your IP/domain appeared in the header.\n\
\n\
I do not appreciate such SPAM coming through your servers, or from\n\
your users.  Please take measures to ensure that this does not\n\
happen again.  This has been logged and an RBL relaying test may have been run.\n\
If your site is relaying and the test was run, you will have been added \n\
to the DSBL distributed server boycott list.\n\
\nSee http://dsbl.org for more details.\n\
\n\
Thank you.\n\n---------------Orignal Message/Cut Here--------------------\n\n";

/* names is a list of standard recipients that will receive spam
   complaints.  Note that it is also used to modify the usernames that
   will be sent mail resulting from whois lookups. */

static const char *names[]=
{
  "postmaster",
  "abuse",
  "root"
};

#ifdef DO_RBL
/* default_rbl_header is the list of e-mail addresses that will
   receive RBL complaints.  At present, this doesn't really work, and
   shouldn't be used.  Notice the %s in the FROM: line.  
   CHANGE THIS */

static char *default_rbl_header=
"To: sword@dorkslayers.com, \n\
CC: relays.ordb.org,  blackholes.intersil.net, spamguard.leadmon.net, blacklist.spambag.org, list.dsbl.org, multihop.dsbl.org, root@localhost\n\
SUBJECT:  RBL SPAM REPORT\n\
FROM: %s\n";

/* default_rbl_message contains the text of the message sent to RBL
   sites.  Notice the %s in the string; this is replaced by the
   spammer's hostname or IP address.
*/
static char *default_rbl_message=
"\n\n----THIS IS AN AUTOMATICALLY GENERATED EMAIL----\n\n\
I have been getting spam from %s (the latest full e-mail is attached\n\
below, as are some of my log entries from earlier incidents).  In each\n\
case, an automated complaint was sent to their sites as well as to a\n\
guess as to who their ISP was and to any contact people that turned up in whois queries.\n\n\
To date, I've received no response,\n\
nor has the spam stopped.  I use a filter that uses your RBL site to\n\
validate mail.  Could you add %s to the RBL database?\n\
\n\
Thanks in advance.\n";

#endif /*DO_RBL*/

#define DEFAULT_PAGER "less"        /* The default pager to use in sending mail */
#define LOCKFILE "/usr/bin/lockfile"   /* Sendmail lockfile program location */
#define SENDMAIL "/usr/sbin/sendmail"  /* Location of sendmail program */

#ifndef SMTP_FWD_PORT
#define SMTP_FWD_PORT 25               /* Port for SMTP */
#endif
static int BadEmails=0;               /* Number of failed emails in a
					 given session */
static char *BadEmailList[MAXBADEMAILS];  /* Where bad emails addrs are
					    stored */

 
/*----------YOU SHOULDN'T HAVE TO CHANGE ANYTHING BELOW THIS---*/

#define ONOFF(x) ((x) ? "on" : "off") 

static int nwhois=0;            /* Number of whois hits */
static char *whois_list[MAXWHOIS];   /* List of email address harvested
				   from whois */

static char lockfile[PATH_MAX]="";  /* The name of the lockfile */
static int NEXCLUDE=0;
static int NNAMES=sizeof(names)/sizeof(char *);
static int depth=0;
static unsigned int spammerslist=0;

static char *exclude_patterns[MAXEXCLUDE];
static regex_t *exclude_patterns_compiled;
static regex_t whois_pattern_compiled;
static regex_t whois_exclude_pattern_compiled;
static char inbuf[BUFMAX];
static unsigned char sendflag=0;
static unsigned char forceflag=0;
static unsigned char verbose=0;
static unsigned char debug=0;
static unsigned char headermode=0xFF;
static unsigned char aggressivemode=0;
static unsigned char wantcopy=0;
static unsigned char wantwhois=0xFF;
static unsigned char summaryflag=0;
static unsigned char haslock=0;
static unsigned char logonly=0;
static unsigned char use_system_sendmail=0;
static unsigned char use_non_mx=0;
static unsigned char send_anonymous=0;

static pid_t timerpid;   /* PID of timer */

#ifdef DO_DSBL
static unsigned char rundsbltest=0xFF;
static int dsblier;
#endif

static char *maindir;
static FILE *spamstream;
static FILE *logstream=NULL;
static char *hostname=NULL;    /* sender's FQDN hostname */
static char *user=NULL;        /* username */



struct summary_totals {
  char *name;
  int spamcount;
  int rblcount;
  unsigned char flag;
};

static struct option long_options[] =
  {
    {"aggressive-whois", no_argument, 0, 'a' },
    {"debug", no_argument, 0, 'd' },
    {"disable-dsbl",no_argument, 0, 'D'},
    {"disable-whois", no_argument, 0, 'W'},
    {"force", no_argument, 0, 'f'},
    {"help", no_argument, 0, 'h' },
    {"include-header-count", no_argument, 0, 'H'},
    {"log-only", no_argument, 0, 'L'},
    {"make-spammer-file", required_argument, 0, 'r'},
    {"message-file", required_argument, 0, 'M'},
    {"send-anonymous", no_argument, 0, 'A' },
    {"send-messages", no_argument, 0, 's' },
    {"subdomain-depth", required_argument, 0, 'p' },
    {"summary", optional_argument, 0, 'S'},
    {"use-non-mx", no_argument, 0, 'X' },
    {"use-sendmail", no_argument, 0, 'U' },
    {"verbose", no_argument, 0, 'v' },
    {"version", no_argument, 0, 'V' },
    {"with-copy", no_argument, 0, 'c' },
    {"with-exclude-file", required_argument, 0, 'e'},
    {"with-log-file", required_argument, 0, 'l'},
    {0, 0, 0, 0}
  };
      
void MyExit(int ier)
{

  signal(SIGINT,SIG_IGN);
  signal(SIGHUP,SIG_IGN);
  signal(SIGTERM,SIG_IGN);
  if(haslock)
    {
      if(access(lockfile,F_OK)==0)
	{
	  if(chmod(lockfile,S_IRUSR|S_IRUSR|S_IROTH|S_IWOTH|S_IRGRP|S_IWGRP))
	    {
	      perror(lockfile);
	    }
	  if(unlink(lockfile))
	    {
	      perror(lockfile);
	    }
	  if(verbose)
	    fprintf(stderr,"spamcomplain:  Lockfile %s removed.\n",lockfile);
	}
    }
  exit(ier);
}

static void kill_timer()
{
  if(timerpid)
    {
      kill(timerpid,SIGKILL);
      if(verbose)
	fprintf(stderr,"spamcomplain:  Killed timer.\n");
      timerpid=0;
    }
}

static FILE *timed_pipe(char *path, char *program, char **argv)
{
  /*  This will run a subprocess and at the same time start a timer
      that will kill the subprocess if it doesn't complete in a
      predfined time.  (i.e., if the subprocess hangs).  It also sets
      up pipes and returns a stream descriptor that allows the parent
      to read the output of the child.  

      The timer's pid is in the global variable timerpid, and should
      be killed by the caller when closing the stream.
*/
  pid_t pid;
  int mypipe[2];
  if(pipe(mypipe))
    {
      perror("Pipe  failed");
      return NULL;
    }
  pid=fork();
  if(pid == 0)
    {
      sprintf(inbuf,"%s/%s",path,program);
      if(verbose)
	{
	  char **pp=argv;
	  fprintf(stderr,"spamcomplain:  Running:  %s",inbuf);
	  while(*++pp)
	    fprintf(stderr," %s",*pp);
	  fputc('\n',stderr);
	}
      close(mypipe[0]);
      dup2(mypipe[1],fileno(stdout));
      execv(inbuf,argv);
      /*  If you get here there's a problem */
      perror(inbuf);
      exit(1);
    }
  else 
    {
      timerpid=fork();
      if(timerpid==0)
	{
	  close(mypipe[0]);
	  close(mypipe[1]);
	  if(verbose)
	    fprintf(stderr,"spamcomplain:  Timer started for %s (%d)\n",
		    program, pid);
	  sleep(SLEEPTIME);
	  kill(pid,SIGKILL);
	  if(verbose)
	    fprintf(stderr,"spamcomplain:  Killed %s (%d)\n", 
		    program, pid);
	  exit(0);
	}
      else
	{
	  close(mypipe[1]);
	  return fdopen(mypipe[0],"r");
	}
    }
}

static void compile_regex(regex_t *c, char *p[], int n, int CFLAGS)
{
  int i;
  char buf[BUFMAX];
  for(i=0;i<n;i++)
    {
      int ier=regcomp(c+i,p[i],CFLAGS);
      if(ier)
	{
	  regerror(ier,c+i,buf,BUFMAX);
	  fprintf(stderr,"regecomp error:  %s (%s)\n",buf,p[i]);
#ifdef DEBUG
	  if(debug&&verbose&&(logstream!=NULL))
	     fprintf(logstream,"regecomp error:  %s (%s)\n",buf,p[i]);
#endif
	  MyExit(1);
	}
    }
}
	  

static void MakeSubDir(char *name)
{
  /* Create subdir of maindir */

  sprintf(inbuf,"%s/%s",maindir,name);
  if(mkdir(inbuf,S_IRWXU)!=0)
    {
      perror(inbuf);
      MyExit(1);
    }
  if(verbose)
    fprintf(stderr,"spamcomplain:  Created %s.\n",inbuf);
}

static void SetupMainDirectory()
{
  /* Find the working directory, or create it if it doesn't exist. */

  char *h;

  if((h=getenv("HOME"))!=NULL)
    {
      char buf[PATH_MAX];
      sprintf(buf,"%s/%s",h,DEFAULT_DIRECTORY);
      maindir=strdup(buf);
      if(verbose)
	fprintf(stderr,"spamcomplain:  Setting working directory to %s\n",maindir);
#ifdef DEBUG
      if(debug&&verbose&&(logstream!=NULL))
	fprintf(logstream,"Setting working directory to %s\n",maindir);
#endif
    }
  else if(access(DEFAULT_DIRECTORY,X_OK)==0)
    {
      maindir=DEFAULT_DIRECTORY;
      if(verbose)
	fprintf(stderr,"spamcomplain:  Setting working directory to %s\n",maindir);    
      return;
    }
  else
    {
      maindir=DEFAULT_PATH;
      if(verbose)
	fprintf(stderr,
		"spamcomplain:  Setting working directory to builtin default %s\n",maindir);
#ifdef DEBUG
      if(debug&&verbose&&(logstream!=NULL))
	fprintf(logstream,
		"spamcomplain:  Setting working directory to builtin default %s\n",maindir);
#endif
    }
  if(access(maindir,X_OK)!=0)
    {
      if(mkdir(maindir,S_IRWXU)!=0)
	{
	  perror(maindir);
	  MyExit(1);
	}
      if(verbose)
	fprintf(stderr,"spamcomplain:  Created %s.\n",maindir);

      MakeSubDir("Copies");
      MakeSubDir("Messages");
      MakeSubDir("dsbl");
    }
}

static void SetupLock()
{
  sprintf(lockfile,"%s/spamcomplain.lock",maindir);
  sprintf(inbuf,"%s %s",LOCKFILE,lockfile);
  if(system(inbuf))
    perror(inbuf);
  else
    haslock=0xFF;

  signal(SIGHUP,MyExit);
  signal(SIGINT,MyExit);
  signal(SIGTERM,MyExit);

  if(verbose||debug)
    fprintf(stderr,"spamcomplain:  Created %s\n",lockfile);
}

static char *get_temp_name(char *base)
{
  char buf[PATH_MAX];

  if(maindir!=NULL)
    sprintf(buf,"%s/%s",maindir,base);
  else
    strcat(buf,base);
  if(mktemp(buf)!=buf)
    {
      perror(buf);
      MyExit(1);
    }
  return strdup(buf);
}

static FILE *open_default_file(char *name, char *mode)
{
  char buf[PATH_MAX];
  FILE *stream;

  if(maindir!=NULL)
    sprintf(buf,"%s/%s",maindir,name);
  else
    sprintf(buf,"%s/%s",DEFAULT_DIRECTORY,name);
  
  if((stream=fopen(buf,mode))==NULL)
    perror(buf);

  return stream;
}

static void setup_extra_exclusions(FILE *stream)
{
  while((NEXCLUDE<MAXEXCLUDE) && (fgets(inbuf,BUFMAX,stream) != NULL))
    {
      char *p=inbuf,*pp;
      while(isspace(*p) && *p)
	p++;
      if((pp=strchr(p,'\n'))!=NULL)
	*pp='\0';
      exclude_patterns[NEXCLUDE++]=strdup(p);
    }
  if(NEXCLUDE)
    {
      exclude_patterns_compiled=(regex_t *)malloc(NEXCLUDE*sizeof(regex_t));
      compile_regex(exclude_patterns_compiled,exclude_patterns,
		    NEXCLUDE,REG_ICASE|REG_EXTENDED);
    }
}

static unsigned char IsHostName(char *nick)
{
  char *p;
  for(p=nick;*p;p++)
    if(!isdigit(*p) && (*p != '.'))
      return 0xFF;
  return 0;
}

static int exclude(char *string)
{
  int j;
  for(j=0;j<NEXCLUDE;j++)
    if(regexec(exclude_patterns_compiled+j,string,0,NULL,'\0')==0)
      goto match;

  if(!IsHostName(string))  /* If the address is numerical, see if it
			   resolves and if any of the hostnames or
			   aliases are excluded. */
    {
      struct in_addr a;

      if(inet_aton(string,&a))
	{
	  struct hostent *p;
	  if((p=gethostbyaddr(&a,sizeof(struct in_addr),AF_INET))!=NULL)
	    {
	      for(j=0;j<NEXCLUDE;j++)
		{
		  if(regexec(exclude_patterns_compiled+j,
			     p->h_name,0,NULL,'\0')==0)
		    goto match;
		  for(;*(p->h_aliases);(p->h_aliases)++)
		    if(regexec(exclude_patterns_compiled+j,
			       *(p->h_aliases),0,NULL,'\0')==0)
		      goto match;
		}
	    }
	}
    }
  return 0;
  match :
    if(verbose)
      fprintf(stderr,"spamcomplain:  Excluding %s by pattern %s.\n",
	      string,exclude_patterns[j]);
  
  return 1;
}

static void usage(char *s)
{
  fprintf(stderr,"\nusage: %s -adfhvDW -r # -S[#] -d[#] -l log_file -p # -M message|file -e file_name host spamfile\n",s);
  fprintf(stderr,"Version: %s\nRequired options for long options are required for short ones also.\n",vcid);
  
  fprintf(stderr,"\t-a, --aggressive-whois\tTurns on more aggessive\n\t\t\t\te-mail addressing based on emails derived from whois hits.\n");
  fprintf(stderr,"\t-c, --with-copy\t\tCreates a copy of the message in Copies subdirectory.\n");
  fprintf(stderr,"\t-d, --debug\t\tTurns on debug. (Keeps message if force is set)\n");
  fprintf(stderr,"\t-f, --force\t\tForces e-mail to be sent.(USE WITH CAUTION!)\n");

  fprintf(stderr,"\t-e, --with-exclude-file=file\tOverrides default exclusion file (%s).\n",
	  DEFAULT_EXCLUDE);
  fprintf(stderr,"\t-h, --help\tgets this message\n");
  fprintf(stderr,"\t-l, --with-log-file=file\tOverrides default log file (%s).\n", 
	  DEFAULT_LOG);
  fprintf(stderr,"\t-L, --log-only\t\tCreate log entry, but don't keep complaint message.\n");
  fprintf(stderr,"\t-p, --subdomain-depth=#\t\tWill try to send mail to subdomains also.\n");
  fprintf(stderr,"\t-r, --make-spammer-file=#\tUse with -S to create a summary file\n\t\t\t\tof IP numbers of spammers for >=# spams.\n");
  fprintf(stderr,"\t-s, --send-messages\t\tPreview and send messages.\n");
  fprintf(stderr,"\t-v, --verbose\t\tMakes operation verbose.\n");
  fprintf(stderr,"\t-H, --include-header-count\tInclude header in log message count.\n");
  fprintf(stderr,"\t-S, --summary[=#]\tGenerates summary of complaints and exits.\n");
  fprintf(stderr,"\t\t1:  Sort by # of complaints (default).\n");
  fprintf(stderr,"\t\t2:  Sort by IP.\n");
  fprintf(stderr,"\t\t3:  Sort by # of RBL complaints.\n");
#ifdef DO_DSBL
  fprintf(stderr,"\t-D, --disable-dsbl\t\tDon\'t run the DSBL test program %s.\n",DSBL_TEST_PROGRAM);
#endif /*DO_DSBL*/
  fprintf(stderr,"\t-A, --send-anonymous\t\tDon't send your email address in the MAIL From:<> SMTP command.\n");
  fprintf(stderr,"\t-X, --use-non-mx\t\tUse A DNS entry if no MX records found.\n");
  fprintf(stderr,"\t-U, --use-sendmail\t\tUse system sendmail, not builtin one.\n");
  fprintf(stderr,"\t-W, --disable-whois\t\tSuppresses all whois queries.\n");
  fprintf(stderr,"\t-M, --with-message-file=message|file\tOverrides default complaint message:\n%s\n", 
	  default_spam_message);
  MyExit(1);
}


static char *readmessagefile(char *name)
{
  FILE *stream;
  struct stat sb;
  char *p;
  if(stat(name,&sb)!=0)
    goto error;
  if((stream=fopen(name,"r"))==NULL)
    goto error;
  if((p=malloc(sb.st_size+1))==NULL)
    goto error;
  if(fread(p,sizeof(char),sb.st_size,stream)!=sb.st_size)
    goto error;
  p[sb.st_size+1]='\0';
  fclose(stream);
  return p;
 error:
  perror(name);
  MyExit(1);
}

static void copy_spam_message(FILE *stream, unsigned int count, unsigned char mode)
{
  /*

  Copy count characters of the message from the spamstream to stream.
  If mode is nonzero, the entire header is copied, followed by up to
  count characters of the message.  If it's zero, the header is
  included in the count.  In either event, each line is prefixed by >
  and indented.

  */

  unsigned int i;
  char c;

  fseek(spamstream,0L,SEEK_SET);

  if(mode)
    {
      char *p;
      while((p=fgets(inbuf,BUFMAX,spamstream))!=NULL)
      {
	fputs(">     ",stream);
	fputs(inbuf,stream);
	if((strncasecmp(inbuf,"to",2)==0)
	   ||(strncasecmp(inbuf,"date",4)==0)
	   ||(strncasecmp(inbuf,"subject",7)==0)
	   )goto DoBody;
      }
      if(p==NULL);
	return;
    }
	    
  DoBody :
    fputs(INDENTSTRING,stream);
  for(i=0;(i < count)&&((c=fgetc(spamstream))!=EOF); i++)
    {
      if(c=='\n')
	fputs(INDENTSTRING,stream);
      else
	fputc(c,stream);
    }
  fputc('\n',stream);
}

static void update_log(char *msg, char *host)
{
  FILE *email;
  time_t t;
  int i;

  if((email=fopen(msg,"r"))==NULL)
    {
      perror(msg);
      return;
    }
  time(&t);
  fprintf(logstream,"\nSPAMCOMPLAINT:  Trigger %s at %s(depth=%d, debug=%s, force=%s, DSBL=%s, log-only=%s)\n",
	  host,
	  asctime(localtime(&t)),
	  depth,ONOFF(debug),ONOFF(forceflag), ONOFF(rundsbltest), ONOFF(logonly));
#ifdef DO_DSBL
  if(rundsbltest&&dsblier)
    fprintf(logstream,"DSBLTEST: %s returned %d\n",
	    DSBL_TEST_PROGRAM,dsblier);
#endif /*DO_DSBL*/
  for(i=0;i<2;i++)
    {
      fgets(inbuf,BUFMAX,email);
      fputs(inbuf,logstream);
    }
  copy_spam_message(logstream,MAXLOG,headermode);
  fclose(email);
}

#ifdef DO_RBL
static void rbl_analysis(char *host)
{
  int count=0;
  char *rbl_mail_tempname;
  char tmp[BUFMAX];
  char *p,*pp;
  FILE *stream;
  time_t t;

  fflush(logstream);
  fseek(logstream,0L,SEEK_SET);
  while(fgets(inbuf,BUFMAX,logstream) != NULL)
    {
      if(strncmp(inbuf,"SPAMCOMPLAINT:",14)==0)
	{
	  if(sscanf(inbuf,"SPAMCOMPLAINT:  Trigger %s",tmp)!=1)
	    {
	      fprintf(stderr,"Log file corrupted:  %s\n",inbuf);
#ifdef DEBUG
	      if(debug&&verbose&&(logstream!=NULL))
		fprintf(logstream,"Log file corrupted:  %s\n",inbuf);
#endif
	      return;
	    }
	  if(strcasecmp(tmp,host)==0)
	    count++;
	}
      else if(strncmp(inbuf,"RBLCOMPLAINT:",13)==0)
	{
	  if(sscanf(inbuf,"RBLCOMPLAINT:  Trigger %s",tmp)!=1)
	    {
	      fprintf(stderr,"Log file corrupted:  %s\n",inbuf);
#ifdef DEBUG
	      if(debug&&verbose&&(logstream!=NULL))
		fprintf(logstream,"Log file corrupted:  %s\n",inbuf);
#endif
	      return;
	    }
	  if(strcasecmp(tmp,host)==0)
	    {
	      fprintf(stderr,"RBL complaint already sent for %s\n",host);
#ifdef DEBUG
	      if(debug&&verbose&&(logstream!=NULL))
		fprintf(logstream,"RBL complaint already sent for %s\n",host);
#endif
	      return;
	    }
	}
    }
  if(count<rbl)
    return;
  rbl_mail_tempname=get_temp_name("RBLXXXXXX");
  if((stream=fopen(rbl_mail_tempname,"w"))==NULL)
    {
      perror(rbl_mail_tempname);
      return;
    }
#ifdef DEBUG
  if(debug&&verbose&&(logstream!=NULL))
    fprintf(logstream,"Opening %s\n",rbl_mail_tempname);
#endif
  if(verbose)
    fprintf(stderr,"spamcomplain:  Opening %s\n",rbl_mail_tempname);
#ifdef DEBUG
  if(debug&&verbose&&(logstream!=NULL))
    fprintf(logstream,"Opening %s\n",rbl_mail_tempname);
#endif
  pp=tmp;
  if((p=getenv("USER"))!=NULL)
    pp+=sprintf(tmp,"%s",p);
  if((p=getenv("HOSTNAME"))!=NULL)
    pp+=sprintf(pp,"@%s",p);
  fprintf(stream,default_rbl_header,tmp);
  fprintf(stream,default_rbl_message,host,host);
  fprintf(stream,"----Spam that triggered this complaint----\n\n");
  copy_spam_message(stream,UINT_MAX,'\0');

  if(count>1)
    {
      int complaint=0;
      fprintf(stream,"\n---Prior Complaints to Sender--\n");
      fseek(logstream,0L,SEEK_SET);
      while(fgets(inbuf,BUFMAX,logstream) != NULL)
	{
	  if(strncmp(inbuf,"SPAMCOMPLAINT:",14)==0)
	    {
	      loop :
		if(sscanf(inbuf,"SPAMCOMPLAINT:  Trigger %s",tmp)!=1)
		  {
		    fprintf(stderr,"Log file corrupted:  %s\n",inbuf);
#ifdef DEBUG
		    if(debug&&verbose&&(logstream!=NULL))
		      fprintf(logstream,"Log file corrupted:  %s\n",inbuf);
#endif
		    return;
		  }

	      if(strcasecmp(tmp,host)==0)
		{
		  fprintf(stream,"\n---Complaint %d---\n",++complaint);
		  fputs(inbuf,stream);
		  while((p=fgets(inbuf,BUFMAX,logstream)) != NULL)
		    {
		      if(strncmp(inbuf,"RBLCOMPLAINT:",13)==0)
			break;
		      if(strncmp(inbuf,"SPAMCOMPLAINT:",14))
			fputs(inbuf,stream);
		      else 
			goto loop;
		    }  
		  if(!p)
		    goto done;
		}
	    }
	}
    }
  done :
    fseek(logstream,0L,SEEK_END);
  fclose(stream);
  time(&t);
  fprintf(logstream,"\nRBLCOMPLAINT:  Trigger %s at %s",
	  host,asctime(localtime(&t)));
  
  sprintf(inbuf,"%s -N never -t < %s", SENDMAIL, rbl_mail_tempname);
  if(forceflag)
    {
      if(system(inbuf))
	perror(inbuf)
      if(!debug)
	unlink(rbl_mail_tempname);
    }
  free(rbl_mail_tempname);
}

#endif /* DO_RBL */

static int compare_hostnames(char *pa, char *pb)
{
  int i;
  for(i=0;i<4;i++)
    {
      int ia=0,ib=0;
      while((*pa) && (*pa != '.'))
	ia=ia*10+ *pa++ -'0';
      while((*pb) && (*pb != '.'))
	ib=ib*10 + *pb++ -'0';
      if(ia!=ib)
	return ia-ib;

      if(*pa)
	pa++;
      else if(*pb)
	return -1;
      else
	return 0;
      if(*pb)
	pb++;
      else
	return 1;
    }
  return 0;
}

int summary_compare_1 (const void *a, const void *b)
{
  const struct summary_totals *da = (const struct summary_totals *) a;
  const struct summary_totals *db = (const struct summary_totals *) b;
  int i;

  if((i=da->spamcount-db->spamcount))
    return i;
  if((i=compare_hostnames(da->name,db->name)))
    return i;
  return da->rblcount-db->rblcount;
}


int summary_compare_2 (const void *a, const void *b)
{
  const struct summary_totals *da = (const struct summary_totals *) a;
  const struct summary_totals *db = (const struct summary_totals *) b;
  int i;

  if((i=compare_hostnames(da->name,db->name)))
    return i;
  if((i=da->spamcount-db->spamcount))
    return i;
  return da->rblcount-db->rblcount;
}

int summary_compare_3 (const void *a, const void *b)
{
  const struct summary_totals *da = (const struct summary_totals *) a;
  const struct summary_totals *db = (const struct summary_totals *) b;
  int i;

  if((i=da->rblcount-db->rblcount))
    return i;
  if((i=da->spamcount-db->spamcount))
    return i;
  return compare_hostnames(da->name,db->name);
}

static void my_h_perror(int err,char *function,char *host)
{
  switch(err)
    {
    case HOST_NOT_FOUND :
      fprintf(stderr,
	      "%s (%s): No such host is known in the data base.\n",
	      function,host);
#ifdef DEBUG
      if(debug&&verbose&&(logstream!=NULL))
	fprintf(stderr,
		"%s (%s): No such host is known in the data base.\n",
		function,host);
#endif
      break;
    case TRY_AGAIN :
      fprintf(logstream,
	      "%s (%s): The name server could not be contacted.\n",
	      function,host);
#ifdef DEBUG
      if(debug&&verbose&&(logstream!=NULL))
	fprintf(stderr,
		"%s (%s): The name server could not be contacted.\n",
		function,host);
#endif
      break;
    case NO_RECOVERY :
      fprintf(logstream,"%s (%s): A non-recoverable error occurred.\n",
	      function,host);
#ifdef DEBUG
      if(debug&&verbose&&(logstream!=NULL))
	fprintf(stderr,"%s (%s): A non-recoverable error occurred.\n",
		function,host);
#endif
      break;
    case NO_ADDRESS :
      fprintf(logstream,"%s (%s): The host database contains an entry for the name, but it doesn't have an associated Internet address.\n",function,host);
#ifdef DEBUG
      if(debug&&verbose&&(logstream!=NULL))
	fprintf(logstream,"%s (%s): The host database contains an entry for the name, but it doesn't have an associated Internet address.\n",function,host);
#endif
      break;
    default :
      fprintf(stderr,"%s (%s) : unknown error\n",function,host);
#ifdef DEBUG
      if(debug&&verbose&&(logstream!=NULL))
	fprintf(logstream,"%s (%s) : unknown error\n",function,host);
#endif
    }
}

static struct hostent *FindHostName(char *string)
{
  /*
    Find the official hostname
  */
  struct hostent *p;
  struct in_addr a;
  if(inet_aton(string,&a))
    {
      if((p=gethostbyaddr(&a,sizeof(struct in_addr),AF_INET))==NULL)
	{
	  if(verbose)
	    my_h_perror(h_errno,"gethostbyaddr",string);
	  p=gethostbyname(string);
	}
    }
  else
    p=gethostbyname(string);
  return p;
}

#ifndef MAXPACKET  // make sure a maximum packet size is declared by BIND
#define MAXPACKET 8192  // BIND maximum packet size
#endif

#define MAXMXHOSTS 10  // max number of MX records returned

#define MXBUFFERSIZE (128 * MAXMXHOSTS)

#ifndef HFIXEDSZ  // make sure header size is declared
#define HFIXEDSZ 12
#endif

// definitions of return codes for your function can go in here..

#define MX_NOBUFFERMEM  -1
#define MX_NODATA -2
#define MX_TEMPFAIL -3
#define MX_UNKNOWNERROR -4
#define MX_QUERROR -5

// define custom data types

typedef union
{
  HEADER hdr;  // define a header structure
  u_char qbuf[MAXPACKET];  // define a query buffer
} mxquery;

static int ZeroMemory( void *ptr, int size)
{
  // zeroes out a memory buffer
  if ( memset( ptr, 0, size) < 0)
    return -1;
  else return 1;
}


static int GetMXRecord( char *dname, char **mxhosts, 
			u_short *mxprefs, char *mxbuf)

{

  /*

  A function that queries a DNS server for MX records for the
  specified host

  host - string containing host name
  
  mxhosts - a pointer to an array of pointers each pointing to an MX record
            (in the same buffer, for efficiency)

  mxprefs - a pointer to an array of unsigned shorts that specify the
            preferances of each MX host

  mxbuf - a pointer to an allocated buffer that will contain all the host

  names (each name's pointer is in the mxhosts array)

  */

  u_char *end, *puChar;  // pointers to end of message generic u_char pointer.
  int i, j, n, nmx;
  char *pByte;  // generic char pointer
  HEADER *hp;  // points to a header struct
  mxquery answer;  // declare an mxquey buffer
  int answers, questions, buflen;

  u_short pref, type, *pPrefs;

  struct hostent *h;  // for the A record, if needed

  // check pointers

  if ( mxprefs == NULL)
    return ( MX_NOBUFFERMEM);

  if ( mxhosts == NULL)
    return ( MX_NOBUFFERMEM);

  if ( mxbuf == NULL)
    return ( MX_NOBUFFERMEM);

  // make query

  errno=0;

  n = res_query( dname, C_IN, T_MX, (u_char *) &answer, sizeof( answer));

  if ( n < 0)

  {

  // handle error conditions

  switch( h_errno)

  {
  case NO_DATA:
  case NO_RECOVERY:
    // no MX RRs, try the A record..
    h = gethostbyname(dname);
    if ( h != NULL)
      {
	// returned a resolved result, store
	
	if ( h->h_name != NULL)
	  {
	    if ( strlen( h->h_name) != 0)
	      snprintf( mxbuf, MXBUFFERSIZE-1, h->h_name);
	  }
	else
	  snprintf( mxbuf, MXBUFFERSIZE-1, dname);

	// set the arrays

	nmx=0;
	mxprefs[nmx]=0;
	mxhosts[nmx]=mxbuf;
	nmx++;
	return( nmx);
      }
    return( MX_NODATA);
    break;
  case TRY_AGAIN:
  case -1:
    // couldn't connect or temp failure
    return( MX_TEMPFAIL);
    break;
  default:
    
    return( MX_UNKNOWNERROR);
    
    break;
    
  }
  
  // who knows what happened
  
  return( MX_UNKNOWNERROR);
  
  }
  
  // make sure we don't exceed buffer length
  
  if ( n > (int)sizeof(answer))
    n = (int)sizeof(answer);
  
  // skip the question portion of the DNS packet
  
  hp = (HEADER *) &answer;
  
  puChar = (u_char *) &answer + HFIXEDSZ;  // point after the header
  
  end = (u_char *) &answer + n;  //point right after the entire answer
  
  pPrefs = mxprefs;  // initialize the pointer to the array of preferences
  
  for( questions = ntohs((u_short)hp->qdcount) ; 
       questions > 0 ; 
       questions--, puChar += n+QFIXEDSZ)
    {
      
      // loop on question count (taken from header), and skip them one by one
      
      if ( (n = dn_skipname(puChar, end)) < 0)
	{
	  // couldn't account for a question portion in the packet.
	  return ( MX_QUERROR);
	}
  }

  // initialize and start decompressing the answer

  nmx = 0;
  buflen = MXBUFFERSIZE-1;
  pByte = mxbuf;  

  // point to start of mx hosts string buffer

  ZeroMemory( mxbuf, MXBUFFERSIZE);
  ZeroMemory( mxhosts, MAXMXHOSTS * sizeof(char *));
  ZeroMemory( pPrefs, MAXMXHOSTS * sizeof(u_short));

  answers = ntohs((u_short)hp->ancount);  // number of answers

  while( (--answers >= 0) && (puChar < end) && (nmx < MAXMXHOSTS-1) )

  {

  // puChar constantly changes (moves forward in the answer buffer)

  // pByte points to the mx buffer, moves forward after we stored
  // a host name

  // decompress the domain's default host name into the buffer so
  // we can skip it and check if it's an MXhost

    if ( (n = dn_expand( (u_char *) &answer, end, puChar, (char *)pByte,
			 buflen)) < 0)
      break;  // error in answer
    
    puChar += n;      /* skip the name, go to its attributes */
      
    GETSHORT( type, puChar);  // get the type and move forward

    puChar += INT16SZ + INT32SZ;  // skip the class and TTL portion of
				  // the answer RR

    GETSHORT( n, puChar);  // get the resource size and move on

    if ( type != T_MX)
      {

	// type of record is somehow NOT an MX record, move on

	puChar += n;
	continue;
      }

    GETSHORT( pref, puChar);  // get the preference of the RR and move on

  if ( (n = dn_expand( (u_char *) &answer, end, 
		       puChar, (char *)pByte,
		       buflen)) < 0)  // expand the MXRR
    break;  //error in decompression
  puChar += n;

  // store it's attributes

  pPrefs[nmx] = pref;
  mxhosts[nmx] = pByte;
  nmx++;
  n = strlen( pByte);
  pByte += n+1;  // make sure it's null terminated, notice the buffer
		 // was set to 0 initially

  buflen -= n+1;  
  }

  // in case the records aren't sorted, bubble sort them

  for( i=0 ; i < nmx ; i++)
    for( j=i+1 ; j < nmx ; j++)
      if ( pPrefs[i] > pPrefs[j])
	{

	  int temp;
	  char *temp2;

	  temp = pPrefs[i];
	  pPrefs[i] = pPrefs[j];
	  pPrefs[j] = temp;
	  temp2 = mxhosts[i];
	  mxhosts[i] = mxhosts[j];
	  mxhosts[j] = temp2;  
	}

  // remove duplicates

  for( i=0 ; i < nmx-1 ; i++)
  {
    if ( strcasecmp( mxhosts[i], mxhosts[i+1]) != 0)
      continue;
    else
      {

	// found a duplicate
	for( j=i+1 ; j < nmx ; j++)
	  {
	    mxhosts[j] = mxhosts[j+1];
	    pPrefs[j] = pPrefs[j+1];

	  }

	nmx--;  // 1 less MX record
      }
  }

  // all done, bug out

  return nmx;
}

static int SendBuffer(int sd, char *buf, int s)
{
  int count=0;
  int rc;
  do
    {
      if((rc=write(sd,buf+count,s-count))<0)
	return rc;
      count += rc;
    }while(count<s);
  return 0;
}

static int CRLFsend(char *buf, char *expect, int sd)
{
  char iobuf[BUFMAX];
  int nread=0;

  if(SendBuffer(sd,buf,strlen(buf)))
    {
      perror(buf);
      return 1;
    }
  if(SendBuffer(sd,"\r\n",2))
    {
      perror(buf);
      return 2;
    }
  do {
    int i;
    if((i=read(sd,iobuf+nread,BUFMAX-nread))<=0)
      {
	perror(buf);
	return 3;
      }
    nread+=i;
    if((iobuf[nread-2]=='\r') && (iobuf[nread-1]=='\n'))
      {
	iobuf[nread-2]='\0';
	goto compare;
      }
  } while(nread<BUFMAX);

  iobuf[BUFMAX-1]='\0';
  fprintf(stderr,"CRLFsend %s:  return buffer not terminated.\n",iobuf);
  compare :
    if(strstr(iobuf,expect)==NULL)
      {
	char *p;
	if((p=strstr(iobuf,"\r\n"))!=NULL)
	  *p='\0';
	fprintf(stderr,"CRLFsend %s\n\texpecting %s, got:\n\t%s\n",
		buf,expect,iobuf);
	return 4;
      }
  return 0;
}
  
static void add_to_bad_list(char *name)
{
  if(BadEmails<MAXBADEMAILS)
    BadEmailList[BadEmails++]=strdup(name);
  else
    fprintf(stderr,
      "You\'ve exceeded the number of allowed failures (%s: %d>%d)\n"
	    ,name,++BadEmails,MAXBADEMAILS);
}


static int dosend(char *destination, char *name)
{
  int sd, rc;
  FILE *stream;
  struct hostent *hp, *hpmx;
  struct sockaddr_in srcaddr, dstaddr;
  char *relay=strchr(destination,'@');
  char iobuf[BUFMAX];
  char *mxhosts[MAXMXHOSTS];
  u_short mxprefs[MAXMXHOSTS];
  char mxbuf[MXBUFFERSIZE];
  int i,nmx;

  if(relay==NULL)
    {
      fprintf(stderr,"dosend:  Invalid destination:  %s\n",destination);
      return 1;
      
    }
  *(relay++)='\0';

  for(rc=0;rc<BadEmails;rc++)
    if(strcasecmp(BadEmailList[rc],relay)==0)
      {
	if(verbose)
	  fprintf(stderr,
	    "This address failed once already.  Mail to %s@%s not sent.\n",
		  destination,relay);
	return 0;
      }

  if(!hostname)
    {
      struct utsname id;

      res_init();
      uname(&id);
      if((hp=gethostbyname(id.nodename))!=NULL)
	hostname=strdup(hp->h_name);
    }
  
  if(!user)
    {
      if((user=getenv("USER"))==NULL)
	user=strdup("postmaster");
    }

  if((relay[0]=='[')&&(relay[strlen(relay)-1]==']'))
    {
      struct in_addr a;
      strcpy(iobuf,relay+1);
      iobuf[strlen(iobuf)-1]='\0';
      if(inet_aton(iobuf,&a))
	{
	  if((hp=gethostbyaddr(&a,sizeof(struct in_addr),AF_INET))==NULL)
	    {
	      if(verbose)
		my_h_perror(h_errno,"gethostbyaddr",iobuf);
	      hp=gethostbyname(iobuf);
	    }
	}
      else
	hp=gethostbyname(relay);

    }
  else
    hp=gethostbyname(relay);

  if(hp==NULL)
    {
      if(verbose)
	my_h_perror(h_errno,"gethostbyname",relay);
      return 1;
    }
  nmx=GetMXRecord(hp->h_name,mxhosts, mxprefs, mxbuf);
  if(nmx<=0)
    {
      fprintf(stderr,"GetMXRecord %s returns %d\n",hp->h_name,nmx);
      if(use_non_mx)
	{
	  hpmx=hp;
	  if(verbose)
	    fprintf(stderr,"Using %s as mail server\n",hp->h_name);
	}
      else
	{
	  add_to_bad_list(relay);
	  return 1;
	}
    }
  else
    {
      if(verbose)
	{
	  fprintf(stderr,"MX servers for %s (%s):\n",relay,hp->h_name);
	  for(i=0;i<nmx;i++)
	    fprintf(stderr,"\t%s\n",mxhosts[i]);
	}
      for(i=0;i<nmx;i++)
	if((hpmx=gethostbyname(mxhosts[i]))!=NULL)
	  goto begin;
      fprintf(stderr,"Problem with all the mailhosts for %s:\n",relay);
      if(!verbose)
	for(i=0;i<nmx;i++)
	  fprintf(stderr,"\t%s\n",mxhosts[i]);
      add_to_bad_list(relay);
      return 1;
    }
 begin: 
  dstaddr.sin_family = hpmx->h_addrtype;

  memcpy((char *) &dstaddr.sin_addr.s_addr, hpmx->h_addr_list[0], 
	 hpmx->h_length);

  dstaddr.sin_port = htons(SMTP_FWD_PORT);
  
  sd = socket(AF_INET, SOCK_STREAM, 0);

  srcaddr.sin_family = AF_INET;
  srcaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  srcaddr.sin_port = htons(0);
  
  if((rc = bind(sd, (struct sockaddr *) &srcaddr, sizeof(srcaddr)))<0)
    {
      perror(hp->h_name);
      shutdown(sd,2);
      return rc;
    }
  if((rc = connect(sd, (struct sockaddr *) &dstaddr, sizeof(dstaddr)))<0)
    {
      perror(hpmx->h_name);
      shutdown(sd,2);
      add_to_bad_list(relay);
      return rc;
    }
  if(verbose)
    fprintf(stderr,"spamcomplain:  connection with %s (relay for%s) established.\n",hpmx->h_name, relay);

  if(read(sd,iobuf,BUFMAX)<=0)
    {
      add_to_bad_list(relay);
      shutdown(sd,2);
      return 2;
    }
  if(strncmp(iobuf,"220",3))
    {
      add_to_bad_list(relay);
      shutdown(sd,2);
      return 2;
    }

  if(verbose)
    fprintf(stderr,"spamcomplain:  remote is running SMTP.\n");

  sprintf(iobuf,"EHLO %s",hostname);
  if((rc=CRLFsend(iobuf,"250", sd))!=0)
    {
      add_to_bad_list(relay);
      goto done;
    }
  
  if(send_anonymous)
    sprintf(iobuf,"MAIL FROM:<>");
  else
    sprintf(iobuf,"MAIL FROM:<%s@%s>",user,hostname);
  if((rc=CRLFsend(iobuf,"250",sd))!=0)
    {
      add_to_bad_list(relay);
      goto done;
    }

  sprintf(iobuf,"RCPT TO:<@%s:%s@%s>",hpmx->h_name,destination,relay);
  if((rc=CRLFsend(iobuf,"250",sd))!=0)
    goto done;

  if((rc=CRLFsend("DATA","354",sd))!=0)
    goto done;

  if((stream=fopen(name,"r"))==NULL)
    {
      perror(name);
      goto done;
    }
  if(send_anonymous==1)
    {
      sprintf(iobuf,"Reply-To: %s@%s",user,hostname);
      if((rc=CRLFsend(iobuf,"250",sd))!=0)
	{
	  fclose(stream);
	  goto done;
	}
    }
  while(fgets(iobuf,BUFMAX-2,stream)!=NULL)
    {
      int s=strlen(iobuf);

      if((s>=1)&&(iobuf[s-1]=='\n'))
	s--;
      iobuf[s++]='\r';
      iobuf[s++]='\n';
      if(SendBuffer(sd,iobuf,s))
	{
	  fclose(stream);
	  goto done;
	}
    }
  if((rc=CRLFsend("\r\n.","250",sd))!=0)
    goto done;
  done :
    CRLFsend("QUIT","221",sd);
  shutdown(sd,2);
  if(rc==0)
    fprintf(stderr,"Mail succesfully sent to %s@%s\n",destination,relay);
  return rc;
}

static int mysendmail(char *filename)
{
  FILE *stream;
  char inbuf[BUFMAX];
  char *p,*pp;
  int rc;

  if((stream=fopen(filename,"r"))==NULL)
    {
      perror(filename);
      return -1;
    }
  if(fscanf(stream,"To: %s\n",inbuf)!=1)
    {
      perror(filename);
      return -1;
    }
  rc=dosend(inbuf,filename);
  if(fscanf(stream,"CC: %[^\n]",inbuf)==1)
    {
      fclose(stream);
      p=inbuf;
      do 
	{
	  if((pp=strchr(p,','))!=NULL)
	    *pp='\0';
	  rc=dosend(p,filename);
	  if(pp)
	    p=pp+2;
	}
      while(pp!=NULL);
    }
  else
    fclose(stream);
  return rc;
}
	      

static void send_messages()
{
  
  /*

    This routine will interactively preview all the messages in the
    .spamcomplain directory, query whether to send them, and
    send/delete them.

  */

  int i;
  char *types[]=
    {
      "Complaint",
#ifdef DO_RBL      
      "RBL",
#endif
      ""
    };

  char *PAGER;

  if(!isatty(fileno(stdin)))
  {
    fprintf(stderr,"You must run this option from a terminal.\n");
    MyExit(1);
  }

  if((PAGER=getenv("PAGER"))==NULL)
      PAGER=DEFAULT_PAGER;

  for(i=0;types[i][0];i++)
    {
      glob_t gl;
      int j;

      sprintf(inbuf,"%s/%s*",maindir,types[i]);
      if((j=glob(inbuf,GLOB_ERR,NULL,&gl)))
	{
	  if(j!=GLOB_NOMATCH)
	    perror(inbuf);
	  continue;
	}
      for(j=0;j<gl.gl_pathc;j++)
	{
	  char c;
	  sprintf(inbuf,"%s %s",PAGER,gl.gl_pathv[j]);
	  if(system(inbuf)!=0)
	    {
	      perror(inbuf);
	      continue;
	    }
	  loop :
	    printf("Send %s [y/n]?  ",gl.gl_pathv[j]);
	  while((c=getchar())=='\n')
	    continue;
	  switch(c)
	    {
	    case 'y' :
	      if(use_system_sendmail)
		{
		  sprintf(inbuf,"%s -N never -t < %s",SENDMAIL, gl.gl_pathv[j]);
		  if(system(inbuf)!=0)
		    perror(inbuf);
		}
	      else 
		mysendmail(gl.gl_pathv[j]);
	    case 'n' :
	      unlink(gl.gl_pathv[j]);
	      break;
	    default :
	      goto loop;
	    }
	}
      for(j=0;j<gl.gl_pathc;j++)
	free(gl.gl_pathv[j]);
      free(gl.gl_pathv);
    }
  MyExit(0);
}


static int list_preview(struct summary_totals *s)
{
  struct hostent *h=FindHostName(s->name);
  FILE *stream;
  char *argv[3];
  char buf[BUFMAX];

  argv[0]=WHOISPROGRAM;
  argv[1]=buf;
  argv[2]=NULL;

  printf("\nLooking up host/domain %s (%s %d/%d )...\n",s->name, 
	   (h != NULL ? h->h_name : ""),
	   s->spamcount, 
	   s->rblcount);
  fflush(stdout);
  if(s->name[0]=='.')
    {
      strcpy(argv[1],s->name+1);
    }
  else
    {
      int n=strlen(s->name)-1;
      strcpy(argv[1],s->name);
      if(s->name[n]=='.')
	argv[1][n]='\0';
    }
	  
  if((stream=timed_pipe(WHOISPATH,WHOISPROGRAM,argv))==NULL)
    {
      perror(WHOISPROGRAM);
      kill_timer();
      MyExit(1);
    }

  while(fgets(inbuf,BUFMAX,stream) != NULL )
    fputs(inbuf,stdout);
  fflush(stdout);
  fclose(stream);
  kill_timer();
  loop :
    printf("\nInclude %s (%s %d/%d ) [y/n]?  ",s->name, 
	   (h != NULL ? h->h_name : ""),
	   s->spamcount, 
	   s->rblcount);
  loop1 :
  switch(getchar())
    {
    case 'y' :
      return 1;
    case 'n' :
      return 0;
    case '\n' :
      goto loop1;
    default :
      goto loop;
    }
}

static void summarize_log()
{
  int h=0;
  int i;
  char tmp[BUFMAX];
  struct summary_totals st[MAXLOGHOSTS];
 
  fseek(logstream,0L,SEEK_SET);
  while(fgets(inbuf,BUFMAX,logstream) != NULL)
    {
      unsigned int sc,rc;
      if(strncmp(inbuf,"SPAMCOMPLAINT:",14)==0)
	{
	  if(sscanf(inbuf,"SPAMCOMPLAINT:  Trigger %s",tmp)!=1)
	    {
	      fprintf(stderr,"Log file corrupted:  %s\n",inbuf);
#ifdef DEBUG
	      if(debug&&verbose&&(logstream!=NULL))
		fprintf(logstream,"Log file corrupted:  %s\n",inbuf);
#endif
	      return;
	    }
	  sc=1;
	  rc=0;
	}
      else if(strncmp(inbuf,"RBLCOMPLAINT:",13)==0)
	{
	  if(sscanf(inbuf,"RBLCOMPLAINT:  Trigger %s",tmp)!=1)
	    {
	      fprintf(stderr,"Log file corrupted:  %s\n",inbuf);
#ifdef DEBUG
	      if(debug&&verbose&&(logstream!=NULL))
		fprintf(logstream,"Log file corrupted:  %s\n",inbuf);
#endif
	      return;
	    }
	  sc=0;
	  rc=1;
	}
      else 
	continue;
      for(i=0;i<h;i++)
	{
	  if(strcasecmp(tmp,st[i].name)==0)
	    {
	      st[i].spamcount+=sc;
	      st[i].rblcount+=rc;
	      break;
	    }
	}
      if(i==h)
	{
	  if(i>=MAXLOGHOSTS)
	    {
	      fprintf(stderr,
		      "Too many log entries; time for some housecleaning!\n");
#ifdef DEBUG
	      if(debug&&verbose&&(logstream!=NULL))
		fprintf(logstream,
		      "Too many log entries; time for some housecleaning!\n");
#endif
	    }
	  else
	    {
	      st[i].name=strdup(tmp);
	      st[i].spamcount=sc;
	      st[i].rblcount=rc;
	      h++;
	    }
	}
    }
  if(h)
    {
      if(h>1)
	{
	  switch(summaryflag)
	    {
	    case 3 :
	      qsort (st,h,sizeof(struct summary_totals), summary_compare_3);
	      break;
	    case 2 :
	      qsort (st,h,sizeof(struct summary_totals), summary_compare_2);
	      break;
	    case 1 :
	    default :
	      qsort (st,h,sizeof(struct summary_totals), summary_compare_1);
	      break;
	    }
	}
      printf("Spam Log Summary\n\n");
      printf("%-20s  %-15s  %-20s\n","Host","Complaints","RBL Complaints");
      for(i=0;i<h;i++)
	printf("%-20s    %-13d    %-18d\n",
	       st[i].name,
	       st[i].spamcount,
	       st[i].rblcount);
      if(spammerslist>0)
	{
	  FILE *stream=NULL;
	  unsigned char written=0;
	  struct summary_totals stlist[MAXLOGHOSTS];
	  int nlist=0;
	  fflush(stdout);
	  sprintf(inbuf,"%s/%s",maindir,SPAMMERS_LIST);
	  if(access(inbuf,F_OK)==0)
	    {
	      char new[PATH_MAX];
	      sprintf(new,"%s.bak",inbuf);
	      printf("Moving %s -> %s.bak\n",SPAMMERS_LIST,SPAMMERS_LIST);
	      if(rename(inbuf,new)==-1)
		{
		  perror(inbuf);
		  return;
		}
	      if((stream=fopen(new,"r"))==NULL)
		perror(new);
	      printf("Scanning %s for prior additions...\n",inbuf);
	      while((nlist<MAXLOGHOSTS)&&
		    (fscanf(stream,"%s",inbuf)==1))
		{
		  stlist[nlist].name=strdup(inbuf);
		  stlist[nlist].spamcount=spammerslist;
		  stlist[nlist].rblcount=0;
		  stlist[nlist].flag=0;
		  printf("%-20s    %-13d    %-18d\n",
			 stlist[nlist].name,
			 stlist[nlist].spamcount,
			 stlist[nlist].rblcount);
		  
		  nlist++;

		}
	      fclose(stream);
	      if(nlist)
		printf("%d priors found\n",nlist);
	    }
	  for(i=0;i<h;i++)
	    {
	      if(st[i].spamcount>=spammerslist)
		{
		  char *name=st[i].name;
		  int j;
		  written=0xFF;
		  if(depth>0)
		    {
		      char *p;
		      
		      if(IsHostName(name))
			{
			  name=strchr(name,'.');
			  for(j=0;(name!=NULL)&&(j<depth);j++)
			    {
			      name++;
			      if((p=strchr(name,'.'))!=NULL)
				if(!exclude(name))
				  sprintf(st[i].name,".%s",name);
			      name=p;
			    }
			}
		      else
			{
			  p=strrchr(name,'.');
			  for(j=0;(p!=NULL)&&(j<depth);j++)
			    {
			      *p='\0';
			      if(*name && (( p=strrchr(name,'.')) !=NULL))
				if(!exclude(name))
				  sprintf(st[i].name,"%s.",name);
			    }
			}
		    }
		  for(j=0;j<nlist;j++)
		    {
		      if(strncasecmp(name,stlist[j].name,strlen(stlist[j].name))==0)
			{
			  stlist[j].spamcount+=st[i].spamcount;
			  stlist[j].rblcount+=st[i].rblcount;
			  break;
			}
		    }
		  if((j==nlist)&&(nlist<MAXLOGHOSTS))
		    {
		      stlist[nlist].name=name;
		      stlist[nlist].spamcount=st[i].spamcount;
		      stlist[nlist].rblcount=st[i].rblcount;
		      stlist[nlist].flag=0xFF;
		      nlist++;
		    }
		  else if(nlist==MAXLOGHOSTS)
		    fprintf(stderr,"Too many entries--recompile\n");
		}
	    }
	  if(nlist)
	    {
	      sprintf(inbuf,"%s/%s",maindir,SPAMMERS_LIST);
	      if((stream=fopen(inbuf,"w"))==NULL)
		{
		  perror(inbuf);
		  MyExit(1);
		}

	      qsort (stlist,nlist,sizeof(struct summary_totals), summary_compare_2);
	      for(i=0;i<nlist;i++)
		{
		  if(stlist[i].flag)
		    {
		      if(list_preview(stlist+i))
			fprintf(stream,"%s\n",stlist[i].name);
		    }
		  else
		    fprintf(stream,"%s\n",stlist[i].name);
		}
	      fclose(stream);
	    }
	}
    }
  MyExit(0);
}

static void harvest_whois(char *path, char *program, char *string)
{
  int i;
  char *nick=strdup(string);
  char *p=nick;
  char *pnext;
  unsigned char HostIsChar=0;
  char inbuf[BUFMAX];

  HostIsChar=IsHostName(nick);

  if(HostIsChar)
    pnext=strchr(p,'.');
  else
    pnext=strrchr(p,'.');

  for(i=0;(i<WHOISDEPTH) && pnext && *p ;i++)
    {
      FILE *stream;
      char *argv[3];
      if(verbose)
	fprintf(stderr,"spamcomplain:  started %s for %s\n", program, p);

      argv[0]=program;
      argv[1]=p;
      argv[2]=NULL;

      if((stream=timed_pipe(path,program,argv))==NULL)
	{
	  perror(inbuf);
	  free(nick);
	  kill_timer();
	  return;
	}
      while(fgets(inbuf,BUFMAX,stream) != NULL)
	{
	  char *pp=inbuf;
	  char *pend=inbuf+strlen(inbuf);
	  regmatch_t matcharray;


	  if(regexec(&whois_exclude_pattern_compiled,inbuf,0,NULL,0)==0)
	    {
	      if(verbose)
		{
		  char *p=strchr(inbuf,'\n');
		  if(p)
		    *p='\0';
		  fprintf(stderr,"spamcomplain:  skipping: %s\n",inbuf);
		}
	      continue;
	    }

	  if(regexec(&whois_pattern_compiled,inbuf,1,&matcharray,0)==0)
	    {
	      inbuf[matcharray.rm_eo]='\0';
	      if(verbose)
		fprintf(stderr,"spamcomplain:  whois redirect: %s %s\n",
			inbuf+matcharray.rm_so, string);
	      harvest_whois(path, inbuf+matcharray.rm_so, string);
	      continue;
	    }

	  while((pp<pend) && ((pp=strchr(pp,'@'))!=NULL)
		&& (nwhois <MAXWHOIS))
	    {
	      char *ppp=pp;
	      int j;

	      while((ppp>inbuf)&&(!isspace(*ppp))
		    &&(strchr(",:;[]",*ppp)==NULL))
		ppp--;
	      if(ppp>inbuf)
		ppp++;
	      pp++;
	      while(*pp && !(isspace(*pp))
		    &&(strchr(",:;[]",*ppp)==NULL))
		pp++;
	      *pp++='\0';
	      for(j=0;j<nwhois;j++)
		{
		  if(strcmp(whois_list[j],ppp)==0)
		    break;
		}
	      if(j==nwhois)
		{
		  char *x=strchr(ppp,'@');
		  if(!exclude(x+1))
		    {
		      whois_list[nwhois++]=strdup(ppp);
		      if(verbose)
			fprintf(stderr,"spamcomplain:  whois finds %s\n",ppp);
		      if(aggressivemode)
			{
			  for(j=0;(j<NNAMES)&&(nwhois<MAXWHOIS);j++)
			    {
			      char buf[BUFMAX];
			      int k;
			      sprintf(buf,"%s%s",names[j],x);
			      for(k=0;k<nwhois;k++)
				{
				  if(strcasecmp(buf,whois_list[k])==0)
				    break;
				}
			      if(k==nwhois)
				{
				  whois_list[nwhois++]=strdup(buf);
				  if(verbose)
				    fprintf(stderr,"spamcomplain:  whois finds %s\n",buf);
				}
			    }
			}
		    }
		}
	    }
	}
      fclose(stream);
      kill_timer();
      if(!HostIsChar)
	{
	  *pnext='\0';
	  pnext=strrchr(nick,'.');
	  p=nick;
	}
      else
	{
	  p=pnext+1;
	  pnext=strchr(p,'.');
	}
	    
    }
  free(nick);
}

int main(int argc, char **argv)
{
  FILE *exclude_stream=NULL;
  FILE *stream;

  char c;
  char *message=default_spam_message;
  char *program=*argv;
  char *host;
  char *mail_tempname;
  unsigned char ccflag=0;
  int i;
  struct hostent *ph;

  while((c=getopt_long(argc,argv,"acfsdr:e:l:hp:M:vHDS::WVLUAX",
		       long_options, &i ))!=-1)
    {
      switch(c)
	{
	case 'a' :
	  aggressivemode=0xFF;
	  break;
	case 'c' :
	  wantcopy=0xFF;
	  break;
	case 'e' :
	  if((exclude_stream=fopen(optarg,"r"))==NULL)
	    perror(optarg);
	  break;
	case 'f' :
	  forceflag=0xFF;
	  break;
	case 'l' :
	  if((logstream=fopen(optarg,"a"))==NULL)
	    perror(optarg);
	  break;
	case 'M' :
	  if(access(optarg,R_OK)==0)
	    message=readmessagefile(optarg);
	  else
	    message=optarg;
	  break;
	case 'p' :
	  depth=atoi(optarg);
	  break;
	case 'd' :
	  debug++;
	case 'v' :
	  verbose++;
	  break;
	case 'L' :
	  logonly=0xFF;
	  break;
	case 'V' :
	  fprintf(stderr,"%s\n",vcid);
	  exit(1);
	case 'r' :
	  spammerslist=atoi(optarg);
	  summaryflag=1;
	  break;
#ifdef DO_DSBL
	case 'D' :
	  rundsbltest=0;
	  break;
#endif
	case 'H' :
	  headermode=0;
	  break;
	case 's' :
	  sendflag++;
	  break;
	case 'S' :
	  if(optarg)
	    summaryflag=atoi(optarg);
	  else
	    summaryflag++;
	  break;
	case 'U' :
	  use_system_sendmail=0xFF;
	  break;
	case 'X' :
	  use_non_mx=0xFF;
	  break;
	case 'A' :
	  send_anonymous++;
	  break;
	case 'W' :
	  wantwhois=0;
	  break;
	case 'h':
	default :
	  usage(program);
	}
    }

  if(verbose)
    {
      fprintf(stderr,"spamcomplain: arguments =");
      for(i=1;i<argc;i++)
	fprintf(stderr," %s",argv[i]);
      fputc('\n',stderr);
    }

  SetupMainDirectory();
  SetupLock();

  if(!logstream)
    logstream=open_default_file(DEFAULT_LOG,"a+");

  if(!exclude_stream)
    exclude_stream=open_default_file(DEFAULT_EXCLUDE,"r");

  if(exclude_stream)
    {
      setup_extra_exclusions(exclude_stream);
      fclose(exclude_stream);
    }

  if(summaryflag)
    summarize_log();

  if(sendflag)
    send_messages();

  argc-=optind;
  argv+=optind;

  if(argc!=2)
    usage(program);

  
  /*  If possible, find the Official hostname and work with it.  This
      maybe better finding hits for subdomains.
  */

  if((ph=FindHostName(argv[0]))!=NULL)
    {
      host=strdup(ph->h_name);
      if(verbose)
	fprintf(stderr,"spamcomplain:  %s resolves to %s\n",argv[0],host);
#ifdef DEBUG
      if(debug&&verbose&&(logstream!=NULL))
	fprintf(logstream,"%s resolves to %s\n",argv[0],host);
#endif
    }
  else
    host=strdup(argv[0]);
  
  if(exclude(host))
    MyExit(0);

#ifdef DO_DSBL
  if(rundsbltest)
    {
      sprintf(inbuf,"%s < %s",DSBL_TEST_PROGRAM,argv[1]);
      dsblier=system(inbuf);
    }
#endif /*DO_DSBL*/

  if(wantwhois)
    {
      compile_regex(&whois_pattern_compiled,&whoispattern,
		    1,REG_ICASE|REG_EXTENDED);
      
      compile_regex(&whois_exclude_pattern_compiled,&whoisexcludepattern,
		    1,REG_ICASE|REG_EXTENDED);
      
      harvest_whois(WHOISPATH,WHOISPROGRAM,host);
    }

  if((spamstream=fopen(argv[1],"r"))==NULL)
    {
      perror(argv[1]);
      MyExit(1);
    }


  mail_tempname=get_temp_name("ComplaintXXXXXX");
  if(verbose)
    fprintf(stderr,"spamcomplain:  Complaint message in %s\n",mail_tempname);
#ifdef DEBUG
  if(debug&&verbose&&(logstream!=NULL))
    fprintf(logstream,"Complaint message in %s\n",mail_tempname);
#endif
  if((stream=fopen(mail_tempname,"w"))==NULL)
    {
      perror(mail_tempname);
      MyExit(1);
    }


  if(!IsHostName(host))
    {
      char *p;
  
      fprintf(stream,"To: %s@[%s]\n",names[0],host);
      if(NNAMES>1)
	{
	  fprintf(stream,"CC: %s@[%s]",names[1],host);
	  for(i=2;i<NNAMES;i++)
	    fprintf(stream,", %s@[%s]",names[i],host);
	  ccflag=0xFF;
	}
      p=strrchr(host,'.');
      for(i=0;(p!=NULL) && (i < depth) ; i++)
	{
	  *p='\0';
	  if(*host && (( p = strrchr(host,'.')) != NULL))
	    {
	      if(!exclude(host))
		{
		  int j;
		  if(!ccflag)
		    {
		      fprintf(stream,"CC:  %s@[%s]",names[0],host);
		      j=1;
		      ccflag=0xFF;
		    }
		  else
		    j=0;
		  for(;j<NNAMES;j++)
		    fprintf(stream,",  %s@[%s]",names[j],host);
		}
	    }
	}
    }
  else
    {
  
      fprintf(stream,"To: %s@%s\n",names[0],host);
      if(NNAMES>1)
	{
	  fprintf(stream,"CC: %s@%s",names[1],host);
	  for(i=2;i<NNAMES;i++)
	    fprintf(stream,", %s@%s",names[i],host);
	  ccflag=0xFF;
	}
      host=strchr(host,'.');
      for(i=0;(host!=NULL)&&(i<depth);i++)
	{
	  char *p;
	  host++;
	  if((p=strchr(host,'.'))!=NULL)
	    {
	      int j;
	      if(!exclude(host))
		{
		  if(!ccflag)
		    {
		      fprintf(stream,"CC: %s@%s",names[0],host);
		      for(j=1;j<NNAMES;j++)
			fprintf(stream,", %s@%s",names[j],host);
		      ccflag=0xFF;
		    }
		  else
		    for(j=0;j<NNAMES;j++)
		      fprintf(stream,", %s@%s",names[j],host);
		}
	      host=p;
	    }
	}
    }
  if(nwhois)   /* Add the results of the whois queries */
    {
      int j;
      if(!ccflag)
	{
	  fprintf(stream,"CC: %s",whois_list[0]);
	  j=1;
	  ccflag=0xFF;
	}
      else
	j=0;
      for(;j<nwhois;j++)
	fprintf(stream,", %s",whois_list[j]);
    }      
  if(ccflag)
    fputc('\n',stream);

  fprintf(stream,"Subject:  Spam From Your Site\n");
  fprintf(stream,"%s\n",message);
  copy_spam_message(stream,UINT_MAX,'\0');
  fclose(stream);
  if(logstream)
    update_log(mail_tempname,argv[0]);
  if(forceflag)
    {
      sprintf(inbuf,"%s -N never -t < %s", SENDMAIL, mail_tempname);
      system(inbuf);
    }
#ifdef DO_RBL
  if(rbl)
    rbl_analysis(argv[0]);
#endif
  if(wantcopy)
    {
      sprintf(inbuf,"cp -p %s %s/Copies",mail_tempname,maindir);
      system(inbuf);
    }
  if((forceflag | logonly ) && !debug)
    unlink(mail_tempname);
  free(mail_tempname);
  MyExit(0);
}
