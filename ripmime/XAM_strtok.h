#ifndef __XAM_STRTOK__
#define __XAM_STRTOK__

struct _txstrtok
{
	char *start;
	char delimeter;
};

char *XAM_strtok( struct _txstrtok *st, char *line, char *delimeters );
int XAM_strncasecmp( char *s1, char *s2, int n );
#endif

