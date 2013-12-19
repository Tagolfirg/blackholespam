

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "XAM_strtok.h"


/*------------------------------------------------------------------------
Procedure:     XAM_strncasecmp ID:1
Purpose:       Portable version of strncasecmp(), this may be removed in later
versions as the strncase* type functions are more widely
implemented
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int XAM_strncasecmp( char *s1, char *s2, int n )
{
	char *ds1 = s1, *ds2 = s2;
	char c1, c2;
	int result = 0;

	while(n > 0)
	{
		c1 = tolower(*ds1);
		c2 = tolower(*ds2);

		if (c1 == c2)
		{
			n--;
			ds1++;
			ds2++;
		}
		else
		{
			result = c2 - c1;
			n = 0;
		}

	}

	return result;

}





/*------------------------------------------------------------------------
Procedure:     XAM_strtok ID:1
Purpose:       A thread safe version of strtok()
Input:
Output:
Errors:
------------------------------------------------------------------------*/
char *XAM_strtok( struct _txstrtok *st, char *line, char *delimeters )
{
	char *stop;
	char *dc;
	char *result = NULL;

	if ( line )
	{
		st->start = line;
	}

	//Strip off any leading delimeters

	dc = delimeters;
	while ((st->start)&&(*dc != '\0'))
	{
		if (*dc == *(st->start))
		{
			st->start++;
			dc = delimeters;
		}
		else dc++;
	}

	// Where we are left, is the start of our token.

	result = st->start;

	//	fprintf(stdout,"DEBUG:%d: start = '%s', delimeters = '%s'\n",__LINE__,st->start, delimeters);

	if ((st->start)&&(st->start != '\0'))
	{
		stop = strpbrk( st->start, delimeters ); /* locate our next delimeter */

		// If we found a delimeter, then that is good.  We must now break the string here
		// and don't forget to store the character which we stopped on.  Very useful bit
		// of information for programs which process expressions.

		if (stop)
		{

			// Store our delimeter.

			st->delimeter = *stop;

			// Terminate our token.

			*stop = '\0';


			// Because we're emulating strtok() behaviour here, we have to
				// absorb all the concurrent delimeters, that is, unless we
				// reach the end of the string, we cannot return a string with
				// no chars.

			stop++;
			dc = delimeters;
			while (*dc != '\0')
			{
				if (*dc == *stop)
				{
					stop++;
					dc = delimeters;
				}
				else dc++;
			} // While

			//			fprintf(stdout,"Loop end: stop = '%c'\n",*stop);

			if (*stop == '\0') st->start = NULL;
			else st->start = stop;

		}
		else {
			st->start = NULL;
			st->delimeter = '\0';
		}
	}
	else  {
		st->start = NULL;
		result = NULL;
	}


	return result;
}


