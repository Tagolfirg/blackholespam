// Abstract logging system used to facilitate multiple modes
// of logging

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdarg.h>

#include "logger.h"


static int _LOGGER_mode = _LOGGER_SYSLOG;
static int _LOGGER_syslog_mode = LOG_MAIL|LOG_INFO;
static FILE *_LOGGER_outf;




/*------------------------------------------------------------------------
 Procedure:     LOGGER_get_file ID:1
 Purpose:       Returns the pointer to the file being used to output logs to
 Input:
 Output:
 Errors:
------------------------------------------------------------------------*/
FILE *LOGGER_get_file( void )
{
	return _LOGGER_outf;
}


/*------------------------------------------------------------------------
 Procedure:     LOGGER_set_output_mode ID:1
 Purpose:       Sets the message/log output method, ie, stderr, stdout
                or syslog
 Input:
 Output:
 Errors:
------------------------------------------------------------------------*/
int LOGGER_set_output_mode( int modechoice )
{
	_LOGGER_mode = modechoice;
	return 0;
}

/*------------------------------------------------------------------------
 Procedure:     LOGGER_set_output_file ID:1
 Purpose:       Sets the output file for when _LOGGER_mode is set to
                _LOGGER_file
 Input:
 Output:
 Errors:
------------------------------------------------------------------------*/
int LOGGER_set_output_file( FILE *f )
{
	_LOGGER_outf = f;
	return 0;
}

/*------------------------------------------------------------------------
 Procedure:     LOGGER_set_syslog_mode ID:1
 Purpose:       Sets the mode that messaging to the syslog daemon will
                be sent as (ie, LOG_MAIL|LOG_INFO)
 Input:
 Output:
 Errors:
------------------------------------------------------------------------*/
int LOGGER_set_syslog_mode( int syslogmode )
{
	_LOGGER_syslog_mode = syslogmode;
	return 0;
}




/*------------------------------------------------------------------------
 Procedure:     LOGGER_set_logfile ID:1
 Purpose:       Opens and setups the internal Log file file pointer with the
                log file as given by lfname
 Input:
 Output:
 Errors:
------------------------------------------------------------------------*/
int LOGGER_set_logfile( char *lfname )
{
	int result = 0;

	_LOGGER_outf = fopen(lfname,"a");
	if (!_LOGGER_outf)
	{
		syslog(1,"LOGGER_set_logfile: ERROR - Cannot open logfile '%s' (%s)",lfname,strerror(errno));
		result = -1;
	}

	return result;
}


/*------------------------------------------------------------------------
 Procedure:     LOGGER_close_logfile ID:1
 Purpose:       Closes the modules log file pointer.
 Input:
 Output:
 Errors:
------------------------------------------------------------------------*/
int LOGGER_close_logfile( void )
{
	int result = 0;

	if (_LOGGER_outf) fclose(_LOGGER_outf);

	return result;
}



int LOGGER_clean_output( char *string, int maxsize )
{
	char newstr[10240];
	char *p, *q;
	int pc;
	int slen = strlen( string );

	p = newstr;
	q = string;
	pc = 0;

	while (slen--)
	{
		// If the string has a % in it, then we need to encode it as
		//	a DOUBLE % symbol.

		if (*q == '%') { *p = '%'; p++; pc++; };

		// Copy the character of the string in
		*p = *q;

		// Move everything along.
		q++;
		p++;
		pc++;

		if ( (pc > 10239) || pc > (maxsize -1) ) { break; }
	}

	*p = '\0';

	snprintf( string, maxsize, "%s", newstr );

	return 0;
}

/*------------------------------------------------------------------------
 Procedure:     LOGGER_log ID:1
 Purpose:       Logs the params as supplied to the required
                output as defined by LOGGER_set_output
 Input:
 Output:
 Errors:
------------------------------------------------------------------------*/
int LOGGER_log( char *format, ...)
{
	va_list ptr;
	char output[10240];

	// get our variable arguments
	va_start(ptr,format);

	// produce output, and spit to the log file
	vsnprintf(output,sizeof(output)-1,format,ptr);

	LOGGER_clean_output( output, 10240 );

	// Send the output to the appropriate output destination
	switch (_LOGGER_mode) {
		case _LOGGER_STDERR:
			fprintf(stderr,"%s\n",output);
			break;
		case _LOGGER_SYSLOG:
			syslog(_LOGGER_syslog_mode,output);
			break;
		case _LOGGER_STDOUT:
			fprintf(stdout,"%s\n",output);
			break;
		case _LOGGER_FILE:
			fprintf(_LOGGER_outf,"%s\n",output);
			fflush(_LOGGER_outf);
			break;
		default:
			fprintf(stdout,"LOGGER-Default: %s\n",output);
	}

	return 0;
}




