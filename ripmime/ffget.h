
/* DEFINES */
#define _MAX_LINE_LEN 1024
#define _FFGET_BUFFER_MAX (8192*8)

#define _FFGET_DEBUG_NORMAL 1
#define _FFGET_DEBUG_PEDANTIC 10

struct _FFGET_FILE
{
	char buffer[_FFGET_BUFFER_MAX +1];
	char *startpoint;
	char *endpoint;
	int FILEEND;
	int FFEOF;
	char c;
	unsigned long int bytes;
	int ungetcset;
	int trueblank;
	char lastchar;
	FILE *f;

};

typedef struct _FFGET_FILE FFGET_FILE;

// Special Flag to indicate a Double CR Line.
extern int FFGET_doubleCR;
extern int FFGET_SDL_MODE;  // Single Char Delimeter


int FFGET_setstream( FFGET_FILE *f, FILE *fi );
#ifdef sgi
short FFGET_fgetc( FFGET_FILE *f );
#else
char FFGET_fgetc( FFGET_FILE *f );
#endif
int FFGET_closestream( FFGET_FILE *f );
int FFGET_ungetc( FFGET_FILE *f, char c );
int FFGET_presetbuffer( FFGET_FILE *f, char *buffer, int size );
char *FFGET_fgets( char *linein, int max_size, FFGET_FILE *f );
int FFGET_raw( FFGET_FILE *f, unsigned char *buffer, int max );
int FFGET_feof( FFGET_FILE *f );
int FFGET_getnewblock( FFGET_FILE *f );
int FFGET_set_watch_SDL( int level );

