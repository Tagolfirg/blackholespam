/* blackhole.h */
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
#ifndef _BLACKHOLE_H
#define _BLACKHOLE_H 1

#ifndef USE_MCONFIG
#include "config.h"
#endif

/* Default Limits */
#include "max.h"
#include "my_string.h"
#include "misc.h"

/* Virus Scanners */
#include "virus.h"

#define MAJOR_VERSION 1
#define MINOR_VERSION 0
#define MINOR_REVISION 9

/* Enable Core Dumps on servers without ulimit -c setup, or set to 0 */
/* #ifndef ENABLE_COREDUMP
#define ENABLE_COREDUMP 1
#endif */

/* Allow users to user /include/file usage */
#ifndef WITH_INCLUDE_FILE
#define WITH_INCLUDE_FILE 1
#endif

/* Allow users to user /include/file usage */
#ifndef WITH_EXEC_REPORT_ACTION
#define WITH_EXEC_REPORT_ACTION 1
#endif

#ifndef BH_EDIT_PROG
#define BH_EDIT_PROG "/opt/blackhole/bin/bhedit"
#endif

#ifndef MAIL_DIR
#define MAIL_DIR "Maildir"
#endif

#ifndef VIRUS_MAIL_DIR
#define VIRUS_MAIL_DIR ".Virus"
#endif

#ifndef SPAM_MAIL_DIR
#define SPAM_MAIL_DIR ".Spam"
#endif

#ifndef VIRUS_MAIL_BOX
#define VIRUS_MAIL_BOX "Inbox.Virus"
#endif

#ifndef SPAM_MAIL_BOX
#define SPAM_MAIL_BOX "Inbox.Spam"
#endif

#ifndef BH_SPOOL_DIR
#define BH_SPOOL_DIR "/var/spool/blackhole"
#endif

#ifndef SM_SPOOL_DIR
#define SM_SPOOL_DIR "/var/spool/mail"
#endif

#ifndef SM_LOCAL_SPOOL
int SPOOLDIR = 0;
#define SM_LOCAL_SPOOL ""
#else
int SPOOLDIR = 1;
#endif

#ifndef LOCKFILE
#define LOCKFILE "/usr/bin/lockfile"
#endif

#ifndef QUEUE_CONFIG
#define QUEUE_CONFIG "/etc/blackhole.conf"
#endif

#if QFILTER == 1
#define QMAIL_QFILTER 1
#define QMAIL_QUEUE 1
#endif

#ifndef BH_CONFIG
#define BH_CONFIG ".blackhole"
#endif

#define ALT_BH_CONFIG ".blackhole"

#ifndef MCAFEE_DAT_DIR
#define MCAFEE_DAT_DIR "/opt/uvscan"
#endif

#ifndef MCAFEE_UVSCAN
#define MCAFEE_UVSCAN "/opt/uvscan/uvscan"
#endif

#ifndef CLAMSCAN_BIN
#define CLAMSCAN_BIN "/usr/local/bin/clamscan"
#endif

#ifndef SQL_USER
#define SQL_USER "blackhole"
#endif

#ifndef SQL_PASS
#define SQL_PASS ""
#endif

#ifndef SQL_SERVER
#define SQL_SERVER "127.0.0.1"
#endif

#ifndef SQL_DOMAIN
#define SQL_DOMAIN "default"
#endif

#ifndef RAZOR_BIN
#define RAZOR_BIN "/usr/bin/razor-check"
#endif

#ifndef PYZOR_BIN
#define PYZOR_BIN "/usr/bin/pyzor"
#endif

#ifndef PERL_BIN
#define PERL_BIN "/usr/bin/perl"
#endif

#ifndef SENDMAIL_BIN
#define SENDMAIL_BIN "/usr/sbin/sendmail"
#endif

#ifndef DNS_SRV
#define DNS_SRV NULL
#endif

#ifndef BOUNCE_MESSAGE
#define BOUNCE_MESSAGE "Sorry, no mailbox here by that name. (#5.1.1)\n"
#endif

#ifndef VIRUS_BOUNCE_MESSAGE
#define VIRUS_BOUNCE_MESSAGE "Attention, you sent a Virus!\n" \
                             "It has been blocked, " \
                             "please use a Virus Scanner on your computer.\n"\
                             "The Virus sent is listed below.";
#endif

#ifndef FOOTER_MESSAGE
#define FOOTER_MESSAGE "This message was scanned by BlackHole (http://iland.net/~ckennedy/blackhole.shtml)\n"
#endif

#ifndef EXEC_PROG
#define EXEC_PROG 0
#endif

#ifndef EXEC_CHECK
#define EXEC_CHECK 0
#endif

/* Mail Directories */
char *maildir = MAIL_DIR;
char *spool_dir = BH_SPOOL_DIR;
char *sendmail_dir = SM_SPOOL_DIR;
char *lockfile = LOCKFILE;
char *spooldir = SM_LOCAL_SPOOL;

/* Config File Locations */
char *default_cfg = QUEUE_CONFIG;
char *config_file = BH_CONFIG;
char *alt_config_file = ALT_BH_CONFIG;
int cfg_int = 0;
int ow_cfg = 0;

/* Virus Scanner Programs */
char *dat_dir = MCAFEE_DAT_DIR;
char *uvscan = MCAFEE_UVSCAN;
char *clamscan = CLAMSCAN_BIN;

/* Razor Script */
char *razor_bin = RAZOR_BIN;
char *perl_bin = PERL_BIN;

/* Pyzor Script */
char *pyzor_bin = PYZOR_BIN;

/* Report Executable */
int exec_report = EXEC_PROG;
char *exec_report_prog = NULL;
char *exec_report_args = NULL;
int exec_check = EXEC_CHECK;

/* Sendmail Binary */
char *sendmail_bin = SENDMAIL_BIN;

/* DNS Server */
char *dns_srv = DNS_SRV;

/* MySQL Settings */
char *sql_user = SQL_USER;
char *sql_pass = SQL_PASS;
char *sql_host = SQL_SERVER;
char *sql_domain = SQL_DOMAIN;

/* Bounce Message */
char *bounce_msg = BOUNCE_MESSAGE;
char *virus_bounce_msg = VIRUS_BOUNCE_MESSAGE;

/* Footer Message */
char *footer_msg = FOOTER_MESSAGE;

#ifndef SMTP_FWD_PORT
#define SMTP_FWD_PORT 25
#endif

/* Option Variables */
FILE *tmp_msg = NULL;
int DEBUG = 0;
int level = 0;
int STOP_WHEN_FOUND = 1;

#ifndef QMAIL_QUEUE
#define QMAIL_QUEUE 0
#endif

#ifndef SENDMAIL
#define SENDMAIL 0
#endif

#ifndef COURIER
#define COURIER 0
#endif

#ifndef SQL_CONFIG
#define SQL_CONFIG 0
#endif

#ifndef ALLINONE
#define ALLINONE 0
#endif

#ifndef STORE_EMAIL
#define STORE_EMAIL 1
#endif

#ifndef VIRUS_SCAN
#define VIRUS_SCAN 0
#endif

#ifndef VIRUS_ALERT
#define VIRUS_ALERT 0
#endif

#ifndef DISINFECT
#define DISINFECT 0
#endif

#ifndef SPAM_SCAN
#define SPAM_SCAN 1
#endif

#ifndef BOUNCE_MSG
#define BOUNCE_MSG 0
#endif

#ifndef SMTP_BOUNCE_MSG
#define SMTP_BOUNCE_MSG 0
#endif

#ifndef CHECK_SENDER
#define CHECK_SENDER 0
#endif

#ifndef WHITE_LIST
#define WHITE_LIST 0
#endif

#ifndef EXPIRE_TIME
#define EXPIRE_TIME 0
#endif

#ifndef CHECK_REVERSE
#define CHECK_REVERSE 0
#endif

#ifndef CHECK_HELO
#define CHECK_HELO 1
#endif

#ifndef PRIORITY
#define PRIORITY 0
#endif

#ifndef CUSTOM_BODY_THRESHHOLD
#define CUSTOM_BODY_THRESHHOLD 1
#endif

#ifndef SPAM_BODY_THRESHHOLD
#define SPAM_BODY_THRESHHOLD 5
#endif

#ifndef PORN_BODY_THRESHHOLD
#define PORN_BODY_THRESHHOLD 3
#endif

#ifndef RACIST_BODY_THRESHHOLD
#define RACIST_BODY_THRESHHOLD 3
#endif

#ifndef USE_MAILDIR
#define USE_MAILDIR 0
#endif

#ifndef VIRUS_SCANNER
#define VIRUS_SCANNER CLAMSCAN
#endif

#ifndef USE_RAZOR
#define USE_RAZOR 0
#endif

#ifndef USE_PYZOR
#define USE_PYZOR 0
#endif

#ifndef USE_LOG
#define USE_LOG 0
#endif

#ifndef LOG_OK
#define LOG_OK 0
#endif

#ifndef LOG_SCORE
#define LOG_SCORE 0
#endif

#ifndef LOG_SIZE
#define LOG_SIZE 0
#endif

#ifndef LOG_IPRELAY
#define LOG_IPRELAY 0
#endif

#ifndef LOG_SENDER
#define LOG_SENDER 0
#endif

#ifndef LOG_RECIPIENT
#define LOG_RECIPIENT 0
#endif

#ifndef LOG_TYPE
#define LOG_TYPE 0
#endif

#ifndef NO_BODY_CHECK_SIGNATURE
#define NO_BODY_CHECK_SIGNATURE 0
#endif

/** Added by: Joe Stump <joe@joestump.net **/
// Sending to STDOUT is turned off by default. Check out
// send_mail_box() for more on how this is done. The -stdout option
// enables this option.
#ifndef SEND_TO_STDOUT
#define SEND_TO_STDOUT 0
#endif

#ifndef SETGID_SENDMAIL
#define SETGID_SENDMAIL 0
#endif

int qmail_queue = QMAIL_QUEUE;
#ifdef QMAIL_QFILTER
int qmail_qfilter = QMAIL_QFILTER;
int envpipe[2];
#endif
#ifndef QMAIL_QFILTER
int qmail_qfilter = 0;
#endif
int qq_read_global = 0;
int pfilter = 0;
int sendmail = SENDMAIL;
int courier = COURIER;
int setgid_sendmail = SETGID_SENDMAIL;
int sqlconfig = SQL_CONFIG;
int allinone = ALLINONE;
int store_email = STORE_EMAIL;
int virusscan = VIRUS_SCAN;
int virus_alert = VIRUS_ALERT;
int virus_delete = 0;
int virus_ret = 0;
int spam_delete = 0;
int disinfect = DISINFECT;
int spam_scan = SPAM_SCAN;
int spamscan = 1;
int footer = 0;
int bouncemsg = BOUNCE_MSG;
int smtp_bouncemsg = SMTP_BOUNCE_MSG;
int check_sender = CHECK_SENDER;
int white_list = WHITE_LIST;
int expire_time = EXPIRE_TIME;
int checkreverse = CHECK_REVERSE;
int checkhelo = CHECK_HELO;
int priority = PRIORITY;
int userazor = USE_RAZOR;
int usepyzor = USE_PYZOR;
int nosignature = NO_BODY_CHECK_SIGNATURE;

#ifdef LIBSPAMC
int spamassassin = 0;
#endif

int use_maildir = USE_MAILDIR;
int use_log = USE_LOG;
int log_ok = LOG_OK;
int log_score = LOG_SCORE;
int log_size = LOG_SIZE;
int log_iprelay = LOG_IPRELAY;
int log_sender = LOG_SENDER;
int log_recipient = LOG_RECIPIENT;
int BODY_SCAN = 0;
int MY_BODY = 0;
int SPAM_BODY = 0;
int PORN_BODY = 0;
int RACIST_BODY = 0;
int CHAR_128 = 0;

int virus_checker = VIRUS_SCANNER;
int found_virus = 0;

int max_ascii_score = 1;
unsigned int ascii_score = 0;
int maxscore = 0;
float score = 0.0;

int maxsize = 0;
int maxsizetrunc = 0;

/* Code for email return */
int EXIT = 0;
int PERMIT = 1;
int DENY = 2;
int ERROR = 3;

/* exit codes */
#define OK          0
#define DEFER       1
#define BLOCK_SPAM  2
#define BLOCK_VIRUS 3

/* Read Config Codes */
#define RC_USER 0
#define RC_SHOW 1
#define RC_OVERWRITEOFF 2
#define RC_GLOBAL 3

/* LIBPCRE Setting */
#define OVECCOUNT 30            /* multiple of 3 */

/* Body scores */
float my_score = 0, spam_score = 0, porn_score = 0, racist_score = 0;
float my_thresh = CUSTOM_BODY_THRESHHOLD;
float spam_thresh = SPAM_BODY_THRESHHOLD;
float porn_thresh = PORN_BODY_THRESHHOLD;
float racist_thresh = RACIST_BODY_THRESHHOLD;

enum log_types
{
  error = 0,
  output,
  syslog,
  sql
};
enum log_types log_type = LOG_TYPE;

enum cfgsec
{
  E = 0,
  MM,
  SM,
  SI,
  SR,
  C,
  CT,
  SCF,
  SC,
  H
};
enum cfgsec cfg_sec = 0;

enum sections
{
  A_NO_MATCH = 0,
  A_MATCH_SUBJECT,
  A_MATCH_EMAIL,
  A_MATCH_RELAY,
  A_MATCH_BLACKHOLE,
  A_MATCH_BODY_SPAM,
  A_MATCH_BODY_PORN,
  A_MATCH_BODY_RACIST,
  A_MATCH_WHITE_LIST,
  A_MATCH_MY_EMAIL,
  A_MATCH_SENDER_DNS,
  A_MATCH_MY_BODY,
  A_MATCH_CHARSET,
  A_MATCH_ASCII_128,
  A_MATCH_REVERSE,
  A_MATCH_EXEC,
  A_MATCH_RAZOR,
  A_MATCH_PYZOR,
  A_MATCH_HEADER,
  A_MATCH_CTYPE,
  A_MATCH_ENC,
  A_MATCH_MXSIZE,
  A_MATCH_RCPTTO,
  A_MATCH_ATTACH,
  A_MATCH_VIRUS,
  MY_RELAY,
  GOOD_EMAIL,
  BAD_EMAIL,
  GOOD_RELAY,
  BAD_RELAY,
  CONFLEVEL,
  BAD_SUB,
  RBL_HOSTS,
  BOUNCE_550,
  SMTP_BOUNCE_550,
  BOUNCE_MES,
  VBOUNCE_MES,
  VIRUS_CHK,
  VIRUS_MSG,
  RBL_CHK,
  SPAM_CHK,
  BODY_CHK_S,
  BODY_CHK_P,
  BODY_CHK_R,
  WHITE_LIST_CHK,
  MY_EMAIL,
  DNS_CHK,
  VIRUS_CL,
  ALLONE,
  BODY_CHK,
  MY_BODY_CHK,
  CHARSETS,
  MAX_ASCII_128,
  EXPIRE,
  REVERSE,
  HELO,
  EXEC,
  RAZOR,
  PYZOR,
  EXCLUDE_RELAY,
  HEADER,
  MAXSCORE,
  NOSIG,
  NOVCHK,
  NOSCHK,
  CTYPE,
  ENC,
  RFWD,
  SFWD,
  VFWD,
  OFWD,
  VDEL,
  DEL,
  MXSIZE,
  MXSIZETRUNC,
  FOOTER,
  FOOTER_MES,
  GOOD_RCPTTO,
  BAD_RCPTTO,
  SPAM_HEADER,
  VIRUS_HEADER,
  BFWD,
  SREPORT,
  BAD_ATTACH,
  CONF_DEBUG,
  SPAM_ASSASSIN_CHK
};
int count = 0;

enum spam_matches
{
  NO_MATCH = 0,
  MATCH_SUBJECT,
  MATCH_EMAIL,
  MATCH_RELAY,
  MATCH_BLACKHOLE,
  MATCH_BODY_SPAM,
  MATCH_BODY_PORN,
  MATCH_BODY_RACIST,
  MATCH_WHITE_LIST,
  MATCH_MY_EMAIL,
  MATCH_SENDER_DNS,
  MATCH_MY_BODY,
  MATCH_CHARSET,
  MATCH_ASCII_128,
  MATCH_REVERSE,
  MATCH_EXEC,
  MATCH_RAZOR,
  MATCH_PYZOR,
  MATCH_HEADER,
  MATCH_CTYPE,
  MATCH_ENC,
  MATCH_MXSIZE,
  MATCH_RCPTTO,
  MATCH_ATTACH,
  MATCH_VIRUS
};
enum spam_matches match = 0;

struct bh_matches
{
  int match;
  char *log_info;
  struct bh_matches *next;
};
struct bh_matches *bh_match, *bh_match_start;

struct bh_actions
{
  int active;
  int one_box;
  int delete;
  int bounce;
  char *bounce_msg;
  char *spam_fwd;
  float score;
  int passthru;
  int exec_report;
  char *exec_report_prog;
  char *exec_report_args;
  int accumulative;
  int isolated;
}
bh_action[] =
{
  {                             /* NO_MATCH */
  0, 0, 0, 0, NULL, NULL, 0.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_SUBJECT */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_EMAIL */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_RELAY */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_BLACKHOLE */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_BODY_SPAM */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_BODY_PORN */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_BODY_RACIST */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_WHITE_LIST */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_MY_EMAIL */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_SENDER_DNS */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_MY_BODY */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_CHARSET */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_ASCII_128 */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_REVERSE */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_EXEC */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_RAZOR */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_PYZOR */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_HEADER */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_CTYPE */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_ENC */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_MXSIZE */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_RCPTTO */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_ATTACH */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* MATCH_VIRUS (place holder) */
  1, 0, 0, 0, NULL, NULL, 1.0, 0, 0, NULL, NULL, 1, 1}
  , {                           /* */
  0, 0, 0, 0, NULL, NULL, 0.0, 0, 0, NULL, NULL, 1, 1}
};

/* Config Structure */
struct config_options
{
  char *section;
  union {
    char *strval;
    int intval;
  } cur;
  char *info;
  int id;
  union {
    char *strval;
    int intval;
  } new;
}
cfg[] =
{
  {"spam_header",
   {""},
   "Format of spam email headers.",
    SPAM_HEADER},
  {"virus_header",
   {""},
   "Format of virus email headers.",
    VIRUS_HEADER},
  {"excluded_relay",
   {""},
   "Relays that you don't want to do any spam checking on.",
    EXCLUDE_RELAY},
  {"no_spam_check",
   {""},
   "Users or email domains you don't want to spam check.",
    NOSCHK},
  {"no_virus_check",
   {""},
   "Users or email domains you don't want to virus check.",
    NOVCHK},
  {"maxscore",
   {""},
   "If greater than 0 then the actions are activated, 1 is good.",
    MAXSCORE},
  {"my_relay",
   {""},
   "Relays your email forwards through, so skip and get the previous relay.",
    MY_RELAY},
  {"bounce",
   {""},
   "Send mail back when trapped in spam mailbox.",
    BOUNCE_550},
  {"smtp_bounce",
   {""},
   "Send bounce when trapped in spam mailbox, use a separate SMTP connection."
   "This option only includes the original headers, not the full message.",
    SMTP_BOUNCE_550},
  {"bounce_msg",
   {""},
   "Message to send back to spammers.",
    BOUNCE_MES},
  {"virus_bounce_msg",
   {""},
   "Message to send back to virus senders.",
    VBOUNCE_MES},
  {"expire",
   {""},
   "Remove email from Spam/Virus mailboxes after this num of days.",
    EXPIRE},
  {"sscan",
   {""},
   "Spam Scan email, turn to 0 for turning off Spam checking.",
    SPAM_CHK},
  {"vscan",
   {""},
   "Virus scan email, turn to 1 for enabling virus checking.",
    VIRUS_CHK},
  {"valert",
   {""},
   "Send back a generic alert to users sending viruses.",
    VIRUS_MSG},
  {"virus_bcc_to",
   {""},
   "Admin email address to bcc on an alert sent to the recpient.",
    BFWD},
  {"vclean",
   {""},
   "Remove viruses from email.",
    VIRUS_CL},
  {"vdelete",
   {""},
   "Don't even save virus email.",
    VDEL},
  {"sdelete",
   {""},
   "Don't even save spam email.",
    DEL},
  {"good_relay",
   {""},
   "Accept mail from these ip hosts/blocks without spam checking.",
    GOOD_RELAY},
  {"bad_relay",
   {""},
   "Deny mail from these ip hosts/blocks.",
    BAD_RELAY},
  {"bad_relay_action",
   {""},
   "",
    A_MATCH_RELAY},
  {"good_email",
   {""},
   "Accept mail from these email addr/domains without spam checking.",
    GOOD_EMAIL},
  {"bad_email",
   {""},
   "Deny mail from these email addr/domains.",
    BAD_EMAIL},
  {"bad_email_action",
   {""},
   "",
    A_MATCH_EMAIL},
  {"bad_subject",
   {""},
   "Regex type matching, takes [^$\\s+] type regular expression tags.",
    BAD_SUB},
  {"bad_subject_action",
   {""},
   "",
    A_MATCH_SUBJECT},
  {"rbl_check",
   {""},
   "Turn on use of RBL lists.",
    RBL_CHK},
  {"rbl_hosts",
   {""},
   "List of RBL hosts to check against.",
    RBL_HOSTS},
  {"level",
   {""},
   "Number of rbl_hosts in list to use for RBL checks.",
    CONFLEVEL},
  {"rbl_check_action",
   {""},
   "",
    A_MATCH_BLACKHOLE},
  {"nosignature",
   {""},
   "Skip checking the email signature during body checking.",
    NOSIG},
  {"body_check_spam",
   {""},
   "User body patterns to check for being spam.",
    BODY_CHK_S},
  {"body_check_spam_action",
   {""},
   "",
    A_MATCH_BODY_SPAM},
  {"body_check_porn",
   {""},
   "User body patterns to check for being porn.",
    BODY_CHK_P},
  {"body_check_porn_action",
   {""},
   "",
    A_MATCH_BODY_PORN},
  {"body_check_racist",
   {""},
   "User body patterns to check for being racist.",
    BODY_CHK_R},
  {"body_check_racist_action",
   {""},
   "",
    A_MATCH_BODY_RACIST},
  {"white_list",
   {""},
   "Only allow email from people on your good email/relay lists.",
    WHITE_LIST_CHK},
  {"white_list_action",
   {""},
   "",
    A_MATCH_WHITE_LIST},
  {"my_email",
   {""},
   "Your email addresses you allow mail sent To:, others will be blocked!!!",
    MY_EMAIL},
  {"my_email_action",
   {""},
   "",
    A_MATCH_MY_EMAIL},
  {"check_dns",
   {""},
   "Check users email address for valid DNS resolution.",
    DNS_CHK},
  {"check_dns_action",
   {""},
   "",
    A_MATCH_SENDER_DNS},
  {"one_box",
   {""},
   "Keep all email blocked in mail email box, no separate boxes.",
    ALLONE},
  {"body_check",
   {""},
   "Use custom body checks from list under my_body section.",
    BODY_CHK},
  {"my_body",
   {""},
   "Custom body checking patterns, takes regular expressions.",
    MY_BODY_CHK},
  {"spamassassin",
   {""},
   "Enables you to use SpamAssassins SPAM checks via libspamc.so",
   SPAM_ASSASSIN_CHK},
  {"body_check_action",
   {""},
   "",
    A_MATCH_MY_BODY},
  {"charsets",
   {""},
   "Only allow these character sets, block any not listed here.",
    CHARSETS},
  {"charsets_action",
   {""},
   "",
    A_MATCH_CHARSET},
  {"ascii_128",
   {""},
   "number of characters to allow that are > 128 bit.",
    MAX_ASCII_128},
  {"ascii_128_action",
   {""},
   "",
    A_MATCH_ASCII_128},
  {"check_reverse",
   {""},
   "Block non-resolving relays used by checking the relays rev DNS.",
    REVERSE},
  {"strict_reverse",
   {""},
   "Block non-resolving relays used by checking the relays rev and fwd DNS.",
    HELO},
  {"check_reverse_action",
   {""},
   "",
    A_MATCH_REVERSE},
  {"exec_check",
   {""},
   "Custom program that you compile the name and args into blackhole"
   " which checks if email is spam and recieves the args of 'ipaddr' and"
   " 'spammsg', you also must tell blackhole the expected return value when"
   " the message is spam.",
    EXEC},
  {"exec_action",
   {""},
   "",
    A_MATCH_EXEC},
  {"razor",
   {""},
   "Use razor check to see if email is spam.",
    RAZOR},
  {"razor_action",
   {""},
   "",
    A_MATCH_RAZOR},
  {"pyzor",
   {""},
   "Use pyzor check to see if email is spam.",
    PYZOR},
  {"pyzor_action",
   {""},
   "",
    A_MATCH_PYZOR},
  {"bad_headers",
   {""},
   "Headers to block.",
    HEADER},
  {"bad_headers_action",
   {""},
   "",
    A_MATCH_HEADER},
  {"bad_ctype",
   {""},
   "Character types to block.",
    CTYPE},
  {"bad_ctype_action",
   {""},
   "",
    A_MATCH_CTYPE},
  {"bad_encoding",
   {""},
   "Charecter encodings to block",
    ENC},
  {"bad_encoding_action",
   {""},
   "",
    A_MATCH_ENC},
  {"smtp_relay",
   {""},
   "Email server to send fwd mail with.",
    RFWD},
  {"spam_fwd",
   {""},
   "Email address to send all caught spam.",
    SFWD},
  {"virus_fwd",
   {""},
   "Email address to send all caught viruses.",
    VFWD},
  {"ok_fwd",
   {""},
   "Email address to send all clean email to.",
    OFWD},
  {"maxbytes",
   {""},
   "Max message size to allow.",
    MXSIZE},
  {"maxbytes_trunc",
   {""},
   "Chop off more than maxbytes of message, make them conform.",
    MXSIZETRUNC},
  {"bad_maxbytes_action",
   {""},
   "",
    A_MATCH_MXSIZE},
  {"footer",
   {""},
   "Enables the placement of a footer message on each email",
   FOOTER},
  {"footer_msg",
   {""},
   "Footer Message to be placed at the bottom of every message.",
   FOOTER_MES},
  {"good_rcptto",
   {""},
   "Email addresses of yours to not do any spam checking for, To: addresses.",
    GOOD_RCPTTO},
  {"bad_rcptto",
   {""},
   "Email addresses of yours to block, like my_email in most ways.",
    BAD_RCPTTO},
  {"bad_rcptto_action",
   {""},
   "",
    A_MATCH_RCPTTO},
  {"sreport",
   {""},
   "Report Spam by running through external program, chosen at build.  "
   "This program will get the args 'iprelay' and 'msgfile' to work with.",
    SREPORT},
  {"bad_attachment",
   {""},
   "Attachments to filter, can be .exe or filename.exe or filename "
   "Regular expressions are able to be used.",
    BAD_ATTACH},
  {"bad_attachment_action",
   {""},
   "",
    A_MATCH_ATTACH},
  {NULL,
   {NULL},
    NULL,
    0,
   {NULL}}
};

#ifndef SPAM_SUBJECT_TAG
#define SPAM_SUBJECT_TAG 1
#endif

#ifndef SPAM_SUBJECT_MSG
#define SPAM_SUBJECT_MSG "SPAM"
#endif

#ifndef SPAM_SUBJECT_INFO
#define SPAM_SUBJECT_INFO 1
#endif

#ifndef SPAM_SUBJECT_SCORE
#define SPAM_SUBJECT_SCORE 0
#endif

#ifndef SPAM_HEADER_VERSION
#define SPAM_HEADER_VERSION 1
#endif

#ifndef SPAM_HEADER_SENDER
#define SPAM_HEADER_SENDER 1
#endif

#ifndef SPAM_HEADER_RELAY
#define SPAM_HEADER_RELAY 1
#endif

#ifndef SPAM_HEADER_MATCH
#define SPAM_HEADER_MATCH 1
#endif

#ifndef SPAM_HEADER_TYPE
#define SPAM_HEADER_TYPE 1
#endif

#ifndef SPAM_HEADER_STATUS
#define SPAM_HEADER_STATUS 1
#endif

/* X-BlackHole Headers Structures */
struct spam_headers
{
  int subject_tag;
  char *subject_msg;
  int subject_info;
  int subject_score;
  int version;
  int sender;
  int relay;
  int match;
  int type;
  int status;
}
spam_header =
{                               /* Subject Tag */
  SPAM_SUBJECT_TAG,             /* MSG */
  SPAM_SUBJECT_MSG,             /* INFO */
  SPAM_SUBJECT_INFO,            /* SCORE */
  SPAM_SUBJECT_SCORE,           /* Version */
    SPAM_HEADER_VERSION,        /* Sender */
    SPAM_HEADER_SENDER,         /* Relay */
    SPAM_HEADER_RELAY,          /* Match */
    SPAM_HEADER_MATCH,          /* Type */
    SPAM_HEADER_TYPE,           /* Status */
SPAM_HEADER_STATUS};

#ifndef VIRUS_SUBJECT_TAG
#define VIRUS_SUBJECT_TAG 1
#endif

#ifndef VIRUS_SUBJECT_MSG
#define VIRUS_SUBJECT_MSG "VIRUS"
#endif

#ifndef VIRUS_SUBJECT_TYPE
#define VIRUS_SUBJECT_TYPE 1
#endif

#ifndef VIRUS_SUBJECT_CLEAN
#define VIRUS_SUBJECT_CLEAN 0
#endif

#ifndef VIRUS_HEADER_VERSION
#define VIRUS_HEADER_VERSION 1
#endif

#ifndef VIRUS_HEADER_SENDER
#define VIRUS_HEADER_SENDER 1
#endif

#ifndef VIRUS_HEADER_RELAY
#define VIRUS_HEADER_RELAY 1
#endif

#ifndef VIRUS_HEADER_MATCH
#define VIRUS_HEADER_MATCH 1
#endif

#ifndef VIRUS_HEADER_TYPE
#define VIRUS_HEADER_TYPE 1
#endif

#ifndef VIRUS_HEADER_STATUS
#define VIRUS_HEADER_STATUS 1
#endif

/* X-BlackHole Headers Structures */
struct virus_headers
{
  int subject_tag;
  char *subject_msg;
  int subject_type;
  int subject_clean;
  int version;
  int sender;
  int relay;
  int match;
  int type;
  int status;
}
virus_header =
{                               /* Subject Tag */
  VIRUS_SUBJECT_TAG,            /* MSG */
  VIRUS_SUBJECT_MSG,            /* TYPE */
  VIRUS_SUBJECT_TYPE,           /* CLEAN */
  VIRUS_SUBJECT_CLEAN,          /* Version */
    VIRUS_HEADER_VERSION,       /* Sender */
    VIRUS_HEADER_SENDER,        /* Relay */
    VIRUS_HEADER_RELAY,         /* Match */
    VIRUS_HEADER_MATCH,         /* Type */
    VIRUS_HEADER_TYPE,          /* Status */
VIRUS_HEADER_STATUS};

/* Spam Error Codes */
char *matches[] = {
  "OK", 
  "Subject", 
  "Email/Domain",
  "Host/Network", 
  "RBL", 
  "Spam",
  "Porn", 
  "Racist",
  "Whitelist", 
  "My RCPTTO",
  "Sender DNS",
  "Custom", 
  "Character Set",
  "ASCII 128+", 
  "Reverse DNS",
  "Custom Prog",
  "Razor",
  "Pyzor",
  "Custom Header",
  "C/Type", 
  "T/Encoding",
  "Size", 
  "Bad RCPTTO",
  "Bad Attachment",
  "Virus",
  '\0'
};

/* Virus Error Codes */
char *viruses[] = {
  "Clean",
  "Infected",
  "Cleaned",
  '\0'
};

/* Maximum options per section */
int maxoptions = MAXOPTION;

unsigned int msg_size = 0;

char *fname = NULL;
char *tmp_file = NULL;
char *spam_file = NULL;
char *virus_file = NULL;
char *final_msg = NULL;
char *virus_type = NULL;
char *mime_dir = NULL;

char *log_info = NULL;
char *version = NULL;
char *timestamp = NULL;
char *username = NULL;
char *homedir = NULL;
char *hostname = NULL;

char *spam_fwd = NULL;
char *virus_fwd = NULL;
char *mail_fwd = NULL;
char *relay_fwd = "127.0.0.1";
char *bcc_fwd = NULL;

char *spam_mail_dir = SPAM_MAIL_DIR;
char *virus_mail_dir = VIRUS_MAIL_DIR;

char *spam_mail_box = SPAM_MAIL_BOX;
char *virus_mail_box = VIRUS_MAIL_BOX;

char *pfilter_args[MAXOPTION] = {
  "sendmail",
  "-i",
  "-f",
  '\0',
};

/* Option Variables */
char *excludedrelays[MAXOPTION];
char *headers[MAXOPTION];
char *charsets[MAXOPTION];
char *mybody[MAXOPTION];
char *myrelays[MAXOPTION];
char *myemail[MAXOPTION];
char *goodemail[MAXOPTION];
char *bademail[MAXOPTION];
char *goodrelays[MAXOPTION];
char *badrelays[MAXOPTION];
char *badsubject[MAXOPTION];
char *noscheck[MAXOPTION];
char *novcheck[MAXOPTION];
char *badctype[MAXOPTION];
char *badencoding[MAXOPTION];
char *goodrcptto[MAXOPTION];
char *badrcptto[MAXOPTION];
char *badattach[MAXOPTION];
char *rblhosts[MAXOPTION] = {
  "relays.osirusoft.com",
  "relays.ordb.org",
  "orbs.dorkslayers.com",
  "blackholes.intersil.net",
  "spamguard.leadmon.net",
  "blacklist.spambag.org",
  "list.dsbl.org",
  "multihop.dsbl.org",
  '\0'
};

/* Functions */
void usage_err(int);
int readconfig(int);
int checkmyrelay(char *, char *[]);
int checkmyemail(char *, char *[]);
int check_dns(char *);
int regexip(char *, char *, char *);
int rbllookup(char *, char *[]);
int rblcheck(int, int, int, int, char *);
int checkgoodemail(char *, char *[]);
int checkbademail(char *, char *[]);
int checkgoodrelay(char *, char *[]);
int checkbadrelay(char *, char *[]);
#if HAVE_LIBPCRE == 1
int check_body(char *);
#endif
void exit_mail(int);
int time_stamp(char[]);
#if WITH_SQL == 1
int sql_config(void);
#endif
#ifdef LIBSPAMC
int call_spamc(FILE *tmp_msg, char *username, int maxscore);
#endif
int check_charset(char *, char *[]);
int check_reverse(char *, char *);
int ascii_128(char *);
int get_section(char *);
int add_option(int, char *);
int virus_scan(void);
int maildir_put(char *, char *, char *, char *, char *, char *);
int send_mail_box(char *, char *, char *, char *);
int mbox_lock(char *);
int mbox_unlock(char *);
int logging(char *);
int expire(char *, char *, int);
int razor_check(void);
int pyzor_check(void);
int get_action(int, char *);
int checkexcluded(char *, char *[]);
int checkheader(char *, char *[]);
int cmd_cmp(char *, char *, int);
void make_match(int);
int check_match(int);
int no_check(char *, char *[]);
int check_ctype(char *, char *[]);
int check_encoding(char *, char *[]);
void internal_settings(void);
int pfilter_put(char *);
void bh_exit(int);
int crlf_write(int, char *, int);
void enable_core(void);
#ifdef QMAIL_QFILTER
int qfilter(char *);
#endif
int bcc_alert(char *, char *, char *, char *, char *);
int extract_tstamp(char *, char *);
void config(void);
int mk_maildir(char *);
int bhedit(char *, char *, char *);
int add_cur_option(int, char *, int);
char bh_pager_in(int);
void bh_pager(void);
void cfgmenu(void);
int get_choice(char *);
int execute(char *, char *, int);
int add_to_array(char *, char *[], int);
int get_file_size(char *);
void list_op(void);
int check_attach(char *, char *[]);
int smtp_bounce(char *, char *, char *, char *);
/** Added by: Joe Stump <joe@joestump.net> **/
int send_to_stdout = SEND_TO_STDOUT;

#endif /* _BLACKHOLE_H */

