#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <ctype.h>

/* Exceptions */
struct exceptions
{
  int a;
  int b;
  int first;
  int last;
}
exceptions[] =
{
  {
  10, 0, 0, 0}
  , {
  0, 0, 0, 0}
};

int cmd_cmp(char *, char *, int);
int usage_err(void);
int mk_bucket(unsigned int, unsigned int, unsigned int, unsigned int, time_t);
int check_ok(unsigned int, unsigned int, unsigned int, unsigned int);
int tc_start(void);
int tc_stop(void);
int tc_add(int, int, int, int, int);
int bh_add(int, int, int, int, int);

struct bucket
{
  unsigned int a;
  unsigned int b;
  unsigned int c;
  unsigned int d;
  int tstamp;
  int start_tstamp;
  int count;
  int net;
  struct bucket *next;
};
struct bucket *buckets, *first_bucket;

extern char *tzname[2];
int pid;

#define MAXLINE 255

int max_bucket_time = 30;
int min_print_count = 10;
int min_shape_count = 15;
int max_rate = 4;

#define TC      "/sbin/tc"
#define INT     "eth0"
#define BW      "10Mbit"
#define PENALTY "1Kbit"

#define IP      "/sbin/ip"
#define BHADD   "route add blackhole"
#define BHDEL   "route del blackhole"

#define DEBUG 0
int debug = 0;
int do_shape = 0;
int do_blackhole = 0;

char *progname = "demon";

int main(int argc, char *argv[])
{
  char *line;
  char *p;
  int i = 0, j = 0;
  char *buffer;
  int a, b, c, d;
  time_t current = 0;

  /* Command Line Args */
  if(argc > 1) {
    for(i = 1; argv[i] && (i <= argc); i++) {
      if((strncmp(argv[i], "-", 1) == 0)
         && (strlen(argv[i]) == 1)) {
        usage_err();
        return 1;
      } else if(!cmd_cmp(argv[i], "-shape", 2)) {
        do_shape = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-nullroute", 2)) {
        do_blackhole = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-debug", 2)) {
        debug = 1;
        continue;
      } else if(!cmd_cmp(argv[i], "-btime", 2)) {
        if(i < (argc - 1) && strncmp(argv[i + 1], "-", 1)) {
          for(j = 0; argv[i + 1][j] != '\0'; j++) {
            if(isdigit(argv[i + 1][j]) == 0) {
              /* Bad Argument Given */
              usage_err();
              fprintf(stderr, "%s: Error, bad option! %s\n",
                      progname, argv[i + 1]);
              return 1;
            }
          }
          max_bucket_time = (int) atoi(argv[i + 1]);
          i++;
        }
        continue;
      } else if(!cmd_cmp(argv[i], "-tcount", 2)) {
        if(i < (argc - 1) && strncmp(argv[i + 1], "-", 1)) {
          for(j = 0; argv[i + 1][j] != '\0'; j++) {
            if(isdigit(argv[i + 1][j]) == 0) {
              /* Bad Argument Given */
              usage_err();
              fprintf(stderr, "%s: Error, bad option! %s\n",
                      progname, argv[i + 1]);
              return 1;
            }
          }
          min_shape_count = (int) atoi(argv[i + 1]);
          i++;
        }
        continue;
      } else if(!cmd_cmp(argv[i], "-pcount", 2)) {
        if(i < (argc - 1) && strncmp(argv[i + 1], "-", 1)) {
          for(j = 0; argv[i + 1][j] != '\0'; j++) {
            if(isdigit(argv[i + 1][j]) == 0) {
              /* Bad Argument Given */
              usage_err();
              fprintf(stderr, "%s: Error, bad option! %s\n",
                      progname, argv[i + 1]);
              return 1;
            }
          }
          min_print_count = (int) atoi(argv[i + 1]);
          i++;
        }
        continue;
      } else if(!cmd_cmp(argv[i], "-rcount", 2)) {
        if(i < (argc - 1) && strncmp(argv[i + 1], "-", 1)) {
          for(j = 0; argv[i + 1][j] != '\0'; j++) {
            if(isdigit(argv[i + 1][j]) == 0) {
              /* Bad Argument Given */
              usage_err();
              fprintf(stderr, "%s: Error, bad option! %s\n",
                      progname, argv[i + 1]);
              return 1;
            }
          }
          max_rate = (int) atoi(argv[i + 1]);
          i++;
        }
        continue;
      } else {
        usage_err();
        return 1;
      }
    }
  }

  if(debug)
    fprintf(stderr,
            "Settings:\n debug = %d\n Active = %d\n Print = %d\n Shape = %d\n BlackHole = %d\n Bucket = %d\n\n",
            debug, do_shape, do_blackhole, min_print_count, min_shape_count,
            max_bucket_time);

  line = (char *) malloc(MAXLINE + 1);
  if(line == NULL)
    return 1;

  buffer = (char *) malloc(MAXLINE + 1);
  if(buffer == NULL)
    return 1;

  /* Clear TC Rules */
  if(do_shape)
    if(tc_stop() == 1)
      fprintf(stderr, "Error Clearing TC Rules\n");

  /* Start TC Rules */
  if(do_shape)
    if(tc_start() == 1)
      fprintf(stderr, "Error Starting TC Rules\n");

  while(fgets(line, 255, stdin) != NULL) {
    if((p = strstr(line, "tcpserver: ")) != NULL) {
      p = strchr(line, ':');
      p++;

      while(isspace(*p) == 0)
        p++;
      p++;

      i = 0;
      while(isspace(*p) == 0) {
        buffer[i++] = *p++;
      }
      buffer[i] = '\0';

      if(strncmp(buffer, "pid", 3) == 0) {
        p++;
        if(sscanf(p, "%d from %d.%d.%d.%d", &pid, &a, &b, &c, &d) == 5) {
          /* Put it in the bucket */
          if(check_ok(a, b, c, d) == 0) {
            if(mk_bucket(a, b, c, d, current) == 1) {
              fprintf(stderr, "Error creating bucket!\n");
              continue;
            }
          }
        } else {
          fprintf(stderr, "missed: %s\n", p);
        }
      }
    }
  }
  return 0;
}

/* Check if part of our network */
int check_ok(unsigned int a, unsigned int b, unsigned int c, unsigned int d)
{
  int i;

  for(i = 0; exceptions[i].a != 0; i++) {
    if((exceptions[i].first == exceptions[i].last) ||
       (exceptions[i].last < exceptions[i].first)) {
      if(a == exceptions[i].a && b == exceptions[i].b &&
         c == exceptions[i].first)
        return 1;
    } else {
      if(a == exceptions[i].a && b == exceptions[i].b &&
         (c >= exceptions[i].first && c <= exceptions[i].last))
        return 1;
    }
  }

  return 0;
}

/* Fill a bucket, clean the buckets, and more */
int mk_bucket(unsigned int a, unsigned int b, unsigned int c, unsigned int d,
              time_t tstamp)
{
  struct tm *t;
  struct bucket *pcur, *plast, *ptmp;
  int found = 0;

  tstamp = time(NULL);
  localtime(&tstamp);
  t = localtime(&tstamp);

  if(first_bucket == NULL) {
    /* Allocate buckets memory */
    buckets = (struct bucket *) malloc(sizeof(struct bucket));
    first_bucket = buckets;

    /* Fill the bucket */
    buckets->a = a;
    buckets->b = b;
    buckets->c = c;
    buckets->d = d;
    buckets->tstamp = tstamp;
    buckets->net = 0;
    buckets->start_tstamp = tstamp;
    buckets->count = 1;

    /* prepare the second bucket */
    buckets->next = (struct bucket *) NULL;
  } else {
    pcur = (struct bucket *) malloc(sizeof(struct bucket));
    plast = (struct bucket *) malloc(sizeof(struct bucket));
    ptmp = (struct bucket *) malloc(sizeof(struct bucket));

    pcur = first_bucket;
    plast = (struct bucket *) NULL;
    ptmp = (struct bucket *) NULL;

    if(debug)
      fprintf(stderr, "--\n");

    do {
      if(debug)
        fprintf(stderr, "(%d) %d %d.%d.%d.%d\n",
                pcur->count, pcur->tstamp, pcur->a, pcur->b, pcur->c, pcur->d);

      /* Check for expiration */
      if((tstamp - pcur->tstamp) > max_bucket_time) {
        if(debug)
          fprintf(stderr, "Max lifetime (%d) for %d.%d.%d.%d\n",
                  ((int) tstamp - pcur->tstamp),
                  pcur->a, pcur->b, pcur->c, pcur->d);

        /* Remove the bucket */
        if(plast != NULL && pcur->next != NULL) {
          /* In Middle */
          ptmp = pcur;
          if(debug)
            fprintf(stderr, "Middle\n");
          pcur = pcur->next;
          ptmp = (struct bucket *) NULL;
          free((struct bucket *) ptmp);
          plast->next = pcur;
        } else if(pcur->next != NULL) {
          /* At Start */
          if(debug)
            fprintf(stderr, "Start\n");
          ptmp = pcur;
          pcur = pcur->next;
          ptmp = (struct bucket *) NULL;
          free((struct bucket *) ptmp);
          first_bucket = pcur;
        } else {
          /* At End */
          if(debug)
            fprintf(stderr, "End\n");
          pcur = (struct bucket *) NULL;
          free((struct bucket *) pcur);
          pcur = plast;
          plast->next = (struct bucket *) NULL;
          break;
        }

        plast = pcur;
        continue;
      }

      /* Check for match */
      if(a == pcur->a && b == pcur->b && c == pcur->c) {
        pcur->count++;

        /* Check for Network */
        if(pcur->d != d && pcur->net == 0) {
          pcur->net = 1;
        }

        /* Print out stats */
        if(pcur->count >= min_print_count) {
          if((((int) tstamp - pcur->start_tstamp) / pcur->count) <= max_rate) {
            /* Print out info */
            fprintf(stderr,
                  "[%-4d] %02d/%02d %02d:%02d:%02d %d %d  %d.%d.%d.%d (%d) rate: %d\n",
                  pcur->count, t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, 
		  t->tm_sec, pid, pcur->tstamp, pcur->a, pcur->b, pcur->c, 
		  pcur->d, d, 
		  (((int) tstamp - pcur->start_tstamp) / pcur->count));
          }
        }

        /* Add Host to TC Rules */
        if(pcur->count >= min_shape_count) {
          if((((int) tstamp - pcur->start_tstamp) / pcur->count) <= max_rate) {
            fprintf(stderr,
                    "BLOCKING: [%-4d] %02d/%02d %02d:%02d:%02d %d %d  %d.%d.%d.%d (%d) rate: %d\n",
                    pcur->count, t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, 
		    t->tm_sec, pid, pcur->tstamp, pcur->a, pcur->b, pcur->c, 
		    pcur->d, d,
                    (((int) tstamp - pcur->start_tstamp) / pcur->count));

            if(do_shape) {
              if(pcur->net == 1) {
                if(tc_add(a, b, c, 0, 24) == 1)
                  fprintf(stderr, "Error Adding to TC Rules\n");
              } else {
                if(tc_add(a, b, c, d, 32) == 1)
                  fprintf(stderr, "Error Adding Host to TC Rules\n");
              }
            } else if(do_blackhole) {
              if(pcur->net == 1) {
                if(bh_add(a, b, c, 0, 24) == 1)
                  fprintf(stderr, "Error Adding to BH Rules\n");
              } else {
                if(bh_add(a, b, c, d, 32) == 1)
                  fprintf(stderr, "Error Adding Host to BH Rules\n");
              }
            }
          }
        }

        pcur->tstamp = tstamp;

        /* Mark as found */
        found = 1;

        /* No longer need to walk the buckets */
        break;
      }
      plast = pcur;
      if(pcur->next != NULL)
        pcur = pcur->next;
      else {

      }
    } while(pcur->next != NULL);

    if(found == 0) {
      /* Print out info */
      if(debug)
        fprintf(stderr, "%02d:%02d:%02d %d %d  %d.%d.%d.%d\n",
                t->tm_hour, t->tm_min, t->tm_sec, pid, (int) tstamp, a, b, c,
                d);

      /* Put into linked list of buckets */
      buckets->next = (struct bucket *) malloc(sizeof(struct bucket));
      buckets = buckets->next;

      /* Fill the bucket */
      buckets->a = a;
      buckets->b = b;
      buckets->c = c;
      buckets->d = d;
      buckets->tstamp = tstamp;
      buckets->start_tstamp = tstamp;
      buckets->count = 1;

      /* prepare the second bucket */
      buckets->next = (struct bucket *) NULL;
    }
  }

  return 0;
}

/* Clear all TC Rules */
int tc_stop(void)
{
  char *cmd;

  cmd = malloc(sizeof TC + sizeof INT + sizeof BW + 64 + 1);
  if(cmd == NULL)
    return 1;
  snprintf(cmd, (sizeof TC + sizeof INT + sizeof BW + 64 + 1),
           "%s qdisc del dev %s root handle 1:0 cbq bandwidth %s avpkt 1000 mpu 64",
           TC, INT, BW);

#if DEBUG == 1
  fprintf(stderr, "Running %s\n", cmd);
#endif

  if(system(cmd)) {
    free(cmd);
    return 1;
  }

  free(cmd);
  return 0;
}

/* Add IPBLOCK/CIDR to IP blackhole Rules */
int bh_add(int a, int b, int c, int d, int cidr)
{
  char *cmd;
  char *ipblock;

  ipblock = (char *) malloc(32 + 1);
  if(ipblock == NULL)
    return 1;
  snprintf(ipblock, (32 + 1), "%d.%d.%d.%d/%d", a, b, c, d, cidr);

  cmd = malloc(sizeof IP + sizeof BHADD + strlen(ipblock) + 77 + 1);
  if(cmd == NULL)
    return 1;
  snprintf(cmd, (sizeof IP + sizeof BHADD + strlen(ipblock) + 77 + 1),
           "%s %s %s", IP, BHADD, ipblock);

#if DEBUG == 1
  fprintf(stderr, "Running %s\n", cmd);
#endif

  if(system(cmd)) {
    free(cmd);
    return 1;
  }

  free(cmd);
  return 0;
}

/* Add IPBLOCK/CIDR to TC Rules */
int tc_add(int a, int b, int c, int d, int cidr)
{
  char *cmd;
  char *ipblock;

  ipblock = (char *) malloc(32 + 1);
  if(ipblock == NULL)
    return 1;
  snprintf(ipblock, (32 + 1), "%d.%d.%d.%d/%d", a, b, c, d, cidr);

  cmd = malloc(sizeof TC + sizeof INT + strlen(ipblock) + 77 + 1);
  if(cmd == NULL)
    return 1;
  snprintf(cmd, (sizeof TC + sizeof INT + strlen(ipblock) + 77 + 1),
           "%s filter add dev %s parent 1:0 protocol ip prio 1 u32 match ip dst %s flowid 1:101",
           TC, INT, ipblock);

#if DEBUG == 1
  fprintf(stderr, "Running %s\n", cmd);
#endif

  if(system(cmd)) {
    free(cmd);
    return 1;
  }

  free(cmd);
  return 0;
}

/* Start Initial TC Rules */
int tc_start()
{
  char *cmd;

  /* ROOT Class */
  cmd = malloc(sizeof TC + sizeof INT + sizeof BW + 64 + 1);
  if(cmd == NULL)
    return 1;
  snprintf(cmd, (sizeof TC + sizeof INT + sizeof BW + 64 + 1),
           "%s qdisc add dev %s root handle 1:0 cbq bandwidth %s avpkt 1000 mpu 64",
           TC, INT, BW);

#if DEBUG == 1
  fprintf(stderr, "Running %s\n", cmd);
#endif

  if(system(cmd)) {
    free(cmd);
    return 1;
  }

  /* Main Parent on ROOT Class */
  cmd = malloc(sizeof TC + sizeof INT + sizeof BW + 128 + 1);
  if(cmd == NULL)
    return 1;
  snprintf(cmd, (sizeof TC + sizeof INT + sizeof BW + 128 + 1),
           "%s class add dev %s parent 1:0 classid 1:1 cbq bandwidth %s rate 1.0Mbit weight 100Kbit prio 8 maxburst 20 avpkt 1000 bounded isolated",
           TC, INT, BW);

#if DEBUG == 1
  fprintf(stderr, "Running %s\n", cmd);
#endif

  if(system(cmd)) {
    free(cmd);
    return 1;
  }

  /* Class for IPBLOCKS to Block */
  cmd =
    malloc(sizeof TC + sizeof INT + sizeof BW + sizeof PENALTY +
           sizeof PENALTY + 106 + 1);
  if(cmd == NULL)
    return 1;
  snprintf(cmd,
           (sizeof TC + sizeof INT + sizeof PENALTY + sizeof PENALTY +
            sizeof BW + 106 + 1),
           "%s class add dev %s parent 1:1 classid 1:101 cbq bandwidth %s rate %s weight %s prio 1 maxburst 1 avpkt 1000 bounded",
           TC, INT, BW, PENALTY, PENALTY);

#if DEBUG == 1
  fprintf(stderr, "Running %s\n", cmd);
#endif

  if(system(cmd)) {
    free(cmd);
    return 1;
  }

  /* SFQ */
  cmd = malloc(sizeof TC + sizeof INT + 57 + 1);
  if(cmd == NULL)
    return 1;
  snprintf(cmd, (sizeof TC + sizeof INT + 57 + 1),
           "%s qdisc add dev %s parent 1:101 sfq quantum 1514b perturb 10", TC,
           INT);

#if DEBUG == 1
  fprintf(stderr, "Running %s\n", cmd);
#endif

  if(system(cmd)) {
    free(cmd);
    return 1;
  }

  free(cmd);
  return 0;
}

int cmd_cmp(char *buffer, char *cmd, int minlength)
{
  char *bp = buffer;
  char *cp = cmd;
  int cur_pos, maxlength;

  maxlength = strlen(cmd);
  if(strlen(buffer) > maxlength)
    return 1;
  else if(strlen(buffer) < minlength)
    return -1;

  for(cur_pos = 1; (*bp) && (*cp); bp++, cp++, cur_pos++) {
    if(cur_pos > maxlength)
      return 1;
    else if(*bp == '\n')
      break;
    else if(*bp != *cp)
      return -1;
  }

  return 0;
}

int usage_err(void)
{
  fprintf(stderr,
          "Usage: %s [-debug][-btime NUM][-tcount NUM][-pcount NUM][-shape][-nullroute]\n",
          progname);
  fprintf(stderr, "\t-shape          Activate Traffic Shaping\n");
  fprintf(stderr, "\t-nullroute      Activate Null Routing\n");
  fprintf(stderr, "\t-btime NUM      Bucket Expiration time\n");
  fprintf(stderr, "\t-tcount NUM     Min connections to Shape at\n");
  fprintf(stderr, "\t-pcount NUM     Min connections to Print info at\n");
  fprintf(stderr,
          "\t-rcount NUM     Max Seconds between each email before blocking\n");
  fprintf(stderr, "\n");
  return 0;
}

