#include <ctype.h>
	/*
	 * strlower
	 *
	 * converts an entire string of chars, up to l to lowercase
	 */
int strlower( char *convertme ){

	char *c = convertme;

	while ( *c != '\0') {*c = tolower(*c); c++;}

	return 0;
	}


