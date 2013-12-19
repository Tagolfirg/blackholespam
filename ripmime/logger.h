
#ifndef __LOGGER__
#define __LOGGER__
// LOGGER.h
//

#define _LOGGER_STDERR 1
#define _LOGGER_STDOUT 2
#define _LOGGER_FILE 3
#define _LOGGER_SYSLOG 4

int LOGGER_log( char *format, ...);
int LOGGER_set_output_mode( int modechoice );
int LOGGER_set_output_file( FILE *f );
int LOGGER_set_syslog_mode( int syslogmode );
int LOGGER_set_logfile( char *lfname );
int LOGGER_close_logfile( void );
FILE *LOGGER_get_file( void );

#endif

