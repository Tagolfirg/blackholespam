/*------------------------------------------------------
*
 * MIME.C
*
 * This file is the core component of the ripMIME
* and other packages
*
* Copyright PLD / Paul L Daniels 2002.
*
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#ifdef MEMORY_DEBUG
#define DEBUG_MEMORY 1
#include xmalloc.h
#endif

#include "XAM_strtok.h"
#include "strlower.h"
#include "ffget.h"
#include "mime.h"
#include "tnef/tnef_api.h"
#include "zstr.h"
#include "MIME_headers.h"


#define _SL 1

#define _ENC_UNKNOWN 0
#define _ENC_BASE64 1
#define _ENC_PLAINTEXT 2
#define _ENC_QUOTED 3
#define _ENC_EMBEDDED 4
#define _ENC_NOFILE -1
#define _MIME_CHARS_PER_LINE 32
#define _MIME_MAX_CHARS_PER_LINE 76
#define _RECURSION_LEVEL_MAX 20

#define _BOUNDARY_CRASH 2

// BASE64 / UUDEC and other binary writing routines use the write buffer (now in v1.2.16.3+)
// 	The "limit" define is a check point marker which indicates that on our next run through
//	either the BASE64 or UUDEC routines, we need to flush the buffer to disk

#define _MIME_WRITE_BUFFER_SIZE 102400
#define _MIME_WRITE_BUFFER_LIMIT (_MIME_WRITE_BUFFER_SIZE -4)



// Debug precodes
#define MIME_DPEDANTIC ((_MIME_debug >= _MIME_DEBUG_PEDANTIC))
#define MIME_DNORMAL   ((_MIME_debug >= _MIME_DEBUG_NORMAL  ))

#define FL __FILE__,__LINE__

/*----Structures-----*/
struct _MIME_info {
	int lastlinewasboundary;	/* Last line we read in had the boundary in it */
	int lastlinewasfrom;		 /* last line we read in had the From: line proceeded by a blank */
	int lastlinewasblank;		/* (part of lastlinewasfrom) */
	int lastencoding;			 /* the encoding specifier last read in */
	int boundarylen;			  /* Length of the boundary */
	char *inputok;				 /* Indicator of file reading sanity */
	char boundary[_MIME_STRLEN_MAX]; 		 /* The boundary */
	char filename[_MIME_STRLEN_MAX];		  /* Filename of current attachment */
	char uudec_name[_MIME_STRLEN_MAX];	// UUDecode name. This is a post-decode information field.

};


/* our base 64 decoder table */
static unsigned char b64[256]={
	128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,\
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,\
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,   62,  128,  128,  128,   63,\
  52,   53,   54,   55,   56,   57,   58,   59,   60,   61,  128,  128,  128,    0,  128,  128,\
 128,    0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,\
  15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,  128,  128,  128,  128,  128,\
 128,   26,   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,   37,   38,   39,   40,\
  41,   42,   43,   44,   45,   46,   47,   48,   49,   50,   51,  128,  128,  128,  128,  128,\
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,\
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,\
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,\
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,\
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,\
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,\
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,\
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128 \
	};

static unsigned char hexconv[256]={
	0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    0,    0,    0,    0,    0,    0,\
   0,   10,   11,   12,   13,   14,   15,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,   10,   11,   12,   13,   14,   15,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,\
   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0 \
};

static unsigned char uudec[256]={
	32,   33,   34,   35,   36,   37,   38,   39,   40,   41,   42,   43,   44,   45,   46,   47,\
  48,   49,   50,   51,   52,   53,   54,   55,   56,   57,   58,   59,   60,   61,   62,   63,\
   0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,   15,\
  16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   26,   27,   28,   29,   30,   31,\
  32,   33,   34,   35,   36,   37,   38,   39,   40,   41,   42,   43,   44,   45,   46,   47,\
  48,   49,   50,   51,   52,   53,   54,   55,   56,   57,   58,   59,   60,   61,   62,   63,\
   0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,   15,\
  16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   26,   27,   28,   29,   30,   31,\
  32,   33,   34,   35,   36,   37,   38,   39,   40,   41,   42,   43,   44,   45,   46,   47,\
  48,   49,   50,   51,   52,   53,   54,   55,   56,   57,   58,   59,   60,   61,   62,   63,\
   0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,   15,\
  16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   26,   27,   28,   29,   30,   31,\
  32,   33,   34,   35,   36,   37,   38,   39,   40,   41,   42,   43,   44,   45,   46,   47,\
  48,   49,   50,   51,   52,   53,   54,   55,   56,   57,   58,   59,   60,   61,   62,   63,\
   0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,   15,\
  16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   26,   27,   28,   29,   30,   31 \
};




char OK[]="OKAY";

static char scratch[1024];

/* How many attachments have we produced */
int filecount = 0;

/* If the attachment has no name, then we will need it to have one (else how are you going store it on your system ? */
char blankfileprefix[_MIME_STRLEN_MAX]="textfile";

/* Verbosity - talk as we walk through the MIMEpack to the shell */
int _verbosity = 0;

/* Debug - Do we talk in detail as we decode... */
int _MIME_debug = 0;

/* Our logging options */
int syslogging = 0;
int stderrlogging = 1;

/* filename options */
int _MIME_no_uudecode = 0;
int _unique_names = 0;
int _no_paranoid = 0;
int _rename_method = _MIME_RENAME_METHOD_INFIX;

/* The name of the file which will contain all the non-attachment
* lines from the MIMEpack
*/
char headersname[_MIME_STRLEN_MAX]="_headers_";

char MIME_tmpdir[_MIME_STRLEN_MAX];

/* The variable that indicates (if not zero) that we are to dump our
* non-attachment lines to the file "headersname"
*/
int _dump_headers = 0;


/* Attachment count - how many attachment with FILENAMES */
int _attachment_count = 0;

/* Current line read number */
int _current_line = 0;

/* if we dont want nameless-files, this is non-zero */
int _no_nameless = 0;

/* Are we going to handle mailbox format */
int _mailbox_format = 0;

/* File pointer for the headers output */
FILE *headers;

struct _tbsnode {
	char *boundary;
	struct _tbsnode *next;
};

struct _tbsnode *boundarystack = NULL;
char boundarystacksafe[_MIME_STRLEN_MAX];





/*------------------------------------------------------------------------
 Procedure:     MIME_BS_clear ID:1
 Purpose:       Pops all items off the stack and free's the memory
 Input:         none
 Output:
 Errors:
------------------------------------------------------------------------*/
int MIME_BS_clear( void )
{
	struct _tbsnode *next;

	while (boundarystack)
	{
		next = boundarystack->next;
		free(boundarystack->boundary);
		free(boundarystack);
		boundarystack = next;
	}

	return 0;
}



/*----------------------------------------------------------
* MIME_BS_push()
*
 * Push a boundary onto the stack */
int MIME_BS_push( char *boundary )
{

	struct _tbsnode *node = malloc(sizeof(struct _tbsnode));


	if (node)
	{
		node->next = boundarystack;
		boundarystack = node;
		boundarystack->boundary = strdup(boundary);
	}
	else
	    {
		if (syslogging > 0) syslog(_SL,"MIME_BS_push(): Cannot allocate memory for PUSH(), %s",strerror(errno));
	}

	return 0;
}


/*----------------------------------------------------------
* MIME_BS_pop()
*
 * pop's the top boundar off */
char *MIME_BS_pop( void )
{

	struct _tbsnode *node = boundarystack;

	if (boundarystack)
	{
		boundarystack = boundarystack->next;
		zstrncpy(boundarystacksafe,node->boundary, _MIME_STRLEN_MAX);
		free(node->boundary);
		free(node);
	}

	return boundarystacksafe;
}

/*----------------------------------------------------------
* MIME_BS_top()
*
 * returns the top item in the stack, without popping off */
char *MIME_BS_top( void )
{

	if (boundarystack)
	{
		return boundarystack->boundary;
	}
	else return NULL;
}

/*----------------------------------------------------------
* MIME_BS_cmp()
*
 */
int MIME_BS_cmp( char *boundary, int len )
{

	char *top, *spot;
	char testspace[1024];
	int testspacelen=1023;
	int spin=1;
	struct _tbsnode *node=boundarystack;
	struct _tbsnode *nodetmp=NULL, *nodedel=NULL;

	if (!boundary) return 0;

	if (len > testspacelen) len = testspacelen;

	snprintf(testspace, testspacelen, "%s", boundary);

	// First, search through the stack looking for a boundary that matches
	// our search criterion
	//
	// When we do find one, we will jump out of this WHILE loop by setting
	// 'spin' to 0.

	while((node)&&(spin))
	{
		top = node->boundary;
		spot = strstr(testspace,top);
		if (spot) spin = 0;
		else node = node->next;
	}

	// If we have a hit on the matching, then, according
	// to nested MIME rules, we must "remove" any previous
	// boundaries
	//
	// We know that we had a HIT in matching if spin == 0, because
	// in our previous code block that's what we set spin to if
	// we find a match

	if (spin == 0)
	{

		// If our "HIT" node is /NOT/ the one on the top of the
		// stack, then we need to pop off and deallocate the nodes
		// PRIOR/Above the hit node.
		//
		// ie, if "NODE" is not the top, then pop off until we
		// do get to the node

		if (node != boundarystack)
		{
			nodetmp = boundarystack;
			while ((nodetmp)&&(nodetmp != node))
			{
				// - Set the node to delete (nodedel) to the current temp
				// node (notetmp)
				// - Increment the nodetmp to the next node in the stack
				// - Free the node to delete (nodedel)

				nodedel = nodetmp;
				nodetmp = nodetmp->next;
				free(nodedel);
			}
			boundarystack = node;
		}
		return 1;

	}
	else return 0;
}







/*------------------------------------------------------------------------
Procedure:     MIME_set_debug ID:1
Purpose:       Sets the debug level for reporting in MIME
Input:         int level : What level of debugging to use, currently there
are only two levels, 0 = none, > 0 = debug info
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_set_debug( int level )
{
	_MIME_debug = level;

	TNEF_set_debug(level);
	MIMEH_set_debug(level);
	return _MIME_debug;
}


/*------------------------------------------------------------------------
Procedure:     MIME_set_no_uudecode ID:1
Purpose:       Sets the uudecode option
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_set_no_uudecode( int level )
{
	_MIME_no_uudecode = level;

	return 1;
}


/*------------------------------------------------------------------------
Procedure:     MIME_set_tmpdir ID:1
Purpose:       Sets the internal Temporary directory name.
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_set_tmpdir( char *setto )
{

	zstrncpy(MIME_tmpdir,setto, _MIME_STRLEN_MAX);

	return 0;
}





/*-------------------------------------------------------
* MIME_set_blankfileprefix
*
* Sets the prefix for blank files
*
 * the blank file prefix is used when (typ) we have text
* attachments, ie, when there is both a HTML and a
* plain-text version of the message in the same email.
*
 */
int MIME_set_blankfileprefix( char *prefix )
{

	/* copy over the prefix name, ensure that we
	* dont break buffers here */
	zstrncpy(blankfileprefix,prefix, _MIME_STRLEN_MAX);

	return 0;
}


/*------------------------------------------------------------------------
Procedure:     MIME_get_blankfileprefix ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
char *MIME_get_blankfileprefix( void )
{
	return blankfileprefix;
}






/*-------------------------------------------------------
* MIME_set_verbosity
*
* By default, MIME reports nothing as its working
* Setting the verbosity level > 0 means that it'll
* report things like the name of the files it's
* writing/extracting.
*
 */
int MIME_set_verbosity( int level )
{

	_verbosity = level;

	TNEF_set_verbosity( level );

	return 0;
}




/*-------------------------------------------------------
* MIME_set_dumpheaders
*
 * By default MIME wont dump the headers to a text file
* but at times this is useful esp for checking
* for new styles of viruses like the KAK.worm
*
 * Anything > 0 will make the headers be saved
*
 */
int MIME_set_dumpheaders( int level )
{

	_dump_headers = level;

	return 0;
}


/*------------------------------------------------------
* MIME_set_headersname
*
* by default, the headers would be dropped to a file
* called '_headers_'.  Using this call we can make
* it pretty much anything we like
*/
int MIME_set_headersname( char *fname )
{

	zstrncpy(headersname, fname, _MIME_STRLEN_MAX);

	return 0;
}




/*------------------------------------------------------------------------
Procedure:     MIME_get_headersname ID:1
Purpose:       Returns a pointer to the current headersname string.
Input:
Output:
Errors:
------------------------------------------------------------------------*/
char *MIME_get_headersname( void )
{
	return headersname;
}



/*-------------------------------------------------------
* MIME_set_syslogging
*
 * By default, syslogging is off, setting the "level" to a value above zero(0)
* will make MIME log to the system
*/
int MIME_set_syslogging( int level )
{

	syslogging = level;
	TNEF_set_syslogging(level);

	return 0;
}


/*-------------------------------------------------------
* MIME_set_stderrlogging
*
 * By default logging is done via stderr, set this to zero (0) to turn off
*/
int MIME_set_stderrlogging(int level)
{

	stderrlogging = level;
	TNEF_set_stderrlogging(level);

	return 0;
}





/*------------------------------------------------------------------------
Procedure:     MIME_set_no_nameless ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_set_no_nameless( int level )
{

	_no_nameless = level;

	return 0;
}






/*------------------------------------------------------------------------
Procedure:     MIME_set_uniquenames ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_set_uniquenames( int level )
{
	_unique_names = level;

	return 0;
}




/*------------------------------------------------------------------------
Procedure:     MIME_set_noparanoid ID:1
Purpose:       If set, will prevent MIME from clobbering what it considers
to be non-safe characters in the file name.
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_set_noparanoid( int level )
{
	_no_paranoid = level;
	return 0;
}




/*------------------------------------------------------------------------
Procedure:     MIME_set_mailboxformat ID:1
Purpose:       If sets the value for the _mailboxformat variable
in MIME, this indicates to functions later on
that they should be aware of possible mailbox
format specifiers.
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_set_mailboxformat( int level )
{
	_mailbox_format = level;
	MIMEH_set_mailbox( level );
	return 0;
}






/*------------------------------------------------------------------------
Procedure:     MIME_set_renamemethod ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_set_renamemethod( int method )
{
	if (( method >= _MIME_RENAME_METHOD_PREFIX ) && ( method <= _MIME_RENAME_METHOD_POSTFIX ))
	{
		_rename_method = method;
	}
	else
	    {
		//		#FIXME - make me report correct values to stderr or syslog
		return -1;
	}

	return 0;
}






/*------------------------------------------------------------------------
Procedure:     MIME_get_attachment_count ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_get_attachment_count( void )
{
	return _attachment_count;
}







/*------------------------------------------------------------------------
 Procedure:     MIME_test_uniquename ID:1
 Purpose:       Checks to see that the filename specified is unique. If it's not
                unique, it will modify the filename
 Input:         char *path: Path in which to look for similar filenames
                char *fname: Current filename
                int method: Method of altering the filename (infix, postfix, prefix)
 Output:
 Errors:
------------------------------------------------------------------------*/
int MIME_test_uniquename( char *path, char *fname, int method )
{

	struct stat buf;

	char newname[_MIME_STRLEN_MAX +1];
	char scratch[_MIME_STRLEN_MAX +1];
	char *frontname, *extention;

	int cleared = 0;
	int count = 1;

	if (!scratch)
	{
		return -1;
	}

	//DEBUG fprintf(stdout,"----------------------------\n");
//DEBUG fprintf(stdout,"mime.c: %d: input = %s\n",__LINE__,fname);

	frontname = extention = NULL;  // shuts the compiler up

	if (method == _MIME_RENAME_METHOD_INFIX)
	{
		zstrncpy(scratch,fname, _MIMEH_STRLEN_MAX);
//		snprintf(scratch,_MIME_STRLEN_MAX,"%s",fname);
		frontname = scratch;
		extention = strrchr(scratch,'.');
		//DEBUG fprintf(stdout,"mime.c: %d: Scratch: %s - %s-%s\n",__LINE__,scratch,frontname,extention);

		if (extention)
		{
			*extention = '\0';
			extention++;
		}
		else
		    {
			method = _MIME_RENAME_METHOD_POSTFIX;
		}
	}

	snprintf(newname,_MIME_STRLEN_MAX,"%s/%s",path,fname);

	while (!cleared)
	{
		if ((stat(newname, &buf) == -1))
		{
			cleared++;
		}
		else
		    {
			if (method == _MIME_RENAME_METHOD_PREFIX)
			{
				snprintf(newname,_MIME_STRLEN_MAX,"%s/%d_%s",path,count,fname);
			}
			else
			    if (method == _MIME_RENAME_METHOD_INFIX)
			{
				snprintf(newname,_MIME_STRLEN_MAX,"%s/%s_%d.%s",path,frontname,count,extention);
			}
			else
			    if (method == _MIME_RENAME_METHOD_POSTFIX)
			{
				snprintf(newname,_MIME_STRLEN_MAX,"%s/%s_%d",path,fname,count);
			}
			count++;
		}
	}

	if (count > 1)
	{
		frontname = strrchr(newname,'/');
		if (frontname) frontname++;
		else frontname = newname;

		zstrncpy(fname, frontname, _MIMEH_FILENAMELEN_MAX); //FIXME - this assumes that the buffer space is at least MIME_STRLEN_MAX sized.
	}

	return 0;
}








/*------------------------------------------------------------------------
Procedure:     MIME_is_file_mime ID:1
Purpose:       Determines if the file handed to it is a MIME type email file.

Input:         file name to analyze
Output:        Returns 0 for NO, 1 for YES, -1 for "Things di
Errors:
------------------------------------------------------------------------*/
int MIME_is_file_mime( char *fname )
{
	char conditions[10][10] = {
		"From: ", "Subject: ", "Date: ", "Content-", "content-", "from: ", "subject: ", "date: " 					};
	int result = 0;
	int hitcount = 0;
	char *line;
	FILE *f;


	f = fopen(fname,"r");
	if (!f)
	{
		syslog(1,"MIME_is_file_mime: Error, cannot open file '%s' for reading (%s)",fname,strerror(errno));
		return 0;
	}

	line = malloc(sizeof(char) *1025);
	if (!line)
	{
		syslog(1,"MIME_is_file_mime: Error, cannot allocate memory for read buffer");
		return 0;
	}

	while ((hitcount < 2)&&(fgets(line,1024,f)))
	{
		for (result = 0; result < 8; result++)
		{
			//DEBUG			fprintf(stdout,"Testing for : %s\n",conditions[result]);
			if (strstr(line,conditions[result])) hitcount++;
		}
	}

	fclose(f);

	if (hitcount >= 2) result = 1;
	else result = 0;

	if (line) free(line);

	return result;
}















/*------------------------------------------------------------------------
 Procedure:     MIME_base64_init ID:1
 Purpose:       Initialise the B64 conversion array.
 Input:         none
 Output:        none
 Errors:        DEPRECATED. DO NOT USE.
------------------------------------------------------------------------*/
int MIME_base64_init( void )
{
	// This function has been replaced with static compile time
	// initialisation of the B64 decoding array
	//

	/*
	int i;

	// preset every encodment to 0x80
	for (i = 0; i < 255; i++) b64[i] = 0x80;

	// put in the capital letters
	for (i = 'A'; i <= 'Z'; i++) b64[i] = 0 + (i - 'A');

	// put in the lowere case letters
	for (i = 'a'; i <= 'z'; i++) b64[i] = 26 + (i - 'a');

	// the digits
	for (i = '0'; i <= '9'; i++) b64[i] = 52 + (i - '0');

	// and our special chars
	b64['+'] = 62;
	b64['/'] = 63;
	b64['='] = 0;
	*/
	syslog(1,"MIME_base64_init(): WARNING - This function is depricated. Please remove from your code");

	return 0;
}






/*------------------------------------------------------------------------
 Procedure:     MIME_clean_MIME_filename ID:1
 Purpose:       Removed spurilous characters from filename strings.
 Input:         char *fname: null terminated character string
 Output:
 Errors:
------------------------------------------------------------------------*/
int MIME_clean_MIME_filename( char *fname, int size )
{
	int fnl = strlen(fname);
	char *fnp, *iso, fname_copy[1024];
	char tmp[1024];
	char *p;
	struct _txstrtok xst;

	/* scan out any directory separators */

 	p = strrchr(fname,'/');
	if (p)
	{
		p++;
		zstrncpy( tmp, p, sizeof(tmp) );
		zstrncpy( fname, tmp, size);

	} else {


		// Check for Windows/DOS backslash seperator

		p = strrchr( fname, '\\' );
		if ( p )
		{
			if ( *(p+1) != '"' )
			{
				p++;
				zstrncpy( tmp, p, sizeof(tmp) );
				zstrncpy( fname, tmp, size );
			}
		}
	}

	// Scan for ? symbols - these are often used to make the email client pass paremeters to the filename

	p = strchr( fname, '?' );
	if ( p )
	{
		*p = '\0';
	}


	if (MIME_DNORMAL) { fprintf(stdout,"MIME_clean_MIME_Filename:%s:%d: fname = %s", __FILE__, __LINE__, fname ); fflush(stdout); }


	if ( (fnl > 2) && (!strchr(fname,' ')) )
	{

		/* if there's no spaces in our MIME_filename */

		if (strstr(fname,"=?"))
		{
			/* we may have an ISO filename */

			fnp = fname;
			iso = XAM_strtok(&xst,fname,"?");

			// name(=?<charset>?<encoding>?<encoded-data>?=).
			/* iso = strtok(fname,"?");  iso encoding prefix  */

			if (iso) iso = XAM_strtok(&xst, NULL,"?"); /* The leading = */
			if (iso) iso = XAM_strtok(&xst, NULL,"?"); /* unknown singe char */
			if (iso) iso = XAM_strtok(&xst, NULL,"?"); /* filename! */
			if (iso) {
				MIME_decode_text_line(iso);
				zstrncpy(fname_copy,iso,sizeof(fname_copy));
				zstrncpy(fname,fname_copy,_MIME_STRLEN_MAX);
			}
		}

		/* if the MIME_filename starts and ends with "'s */
		if ((fname[0] == '\"') && (fname[fnl-1] == '\"'))
		{
			/* reduce the file namelength by two*/
			fnl=-2;

			/* shuffle the MIME_filename chars down */
			memmove(fname,fname+1,fnl);

			/* terminate the string */
			fname[fnl] = '\0';
		} /* if */
	} /* if */

	return 0;
}






/*------------------------------------------------------------------------
 Procedure:     quick_clean_filename ID:1
 Purpose:       Removes non-7bit characers from the filename
 Input:         char *fname: Null terminated string
 Output:
 Errors:
------------------------------------------------------------------------*/
void quick_clean_filename( char *fname, int size )
{
	char tmp[1024];
	char *p = strrchr(fname,'/');

	/* scan out any directory separators */
	if (p)
	{
		p++;
		zstrncpy(tmp,p,sizeof(tmp));
		zstrncpy(fname,tmp,size);
	}
	else if ( (p = strrchr(fname,'\\')))
	{
		p++;
		zstrncpy(tmp,p,sizeof(tmp));
		zstrncpy(fname,tmp,size);
	}


	while (*fname)
	{
		if (_no_paranoid == 0)
		{
			if( !isalnum(*fname) && (*fname != '.') ) *fname='_';
		}
		else
		    {
			if( (*fname < ' ')||(*fname > '~') ) *fname='_';
		}
		fname++;
	}
}







/*------------------------------------------------------------------------
Procedure:     MIME_getchar_start ID:1
Purpose:       This function is used on a once-off basis. It's purpose is to locate a
non-whitespace character which (in the context of its use) indicates
that the commencement of BASE64 encoding data has commenced.
Input:         FFGET f: file stream
Output:        First character of the BASE64 encoding.
Errors:
------------------------------------------------------------------------*/
int MIME_getchar_start( FFGET_FILE *f )
{

	int c;

	/* loop for eternity, as we're "returning out" */
	while (1)
	{

		/* get a single char from file */
		c = FFGET_fgetc(f);

		/* if that char is an EOF, or the char is something beyond
		* ASCII 32 (space) then return */
		if ((c == EOF) || (c > ' '))
		{
			return c;
		}

	} /* while */

	/* Although we shouldn't ever actually get here, we best put it in anyhow */
	return EOF;
}







/*------------------------------------------------------------------------
Procedure:     MIME_is_uuencode_header ID:1
Purpose:       Tries to determine if the line handed to it is a UUencode header.
Input:
Output:        0 = No
1 = Yes
Errors:
------------------------------------------------------------------------*/
int MIME_is_uuencode_header( char *line )
{
	struct _txstrtok tx;
	char buf[1024];
	char *bp,*fp;
	int result = 0;

	// If we're not supposed to be decoding UUencoded files, then return 0
	if (_MIME_no_uudecode) return 0;

	snprintf(buf,1023,"%s",line);

	bp = buf;

	// If you're wondering why we dont check for "begin ",it's because we dont know
	// if begin is followed by a \t or ' ' or some other white space

	if ((bp)&&(strncasecmp(bp,"begin",5)==0))
	{
		fp = NULL;
		bp = XAM_strtok(&tx, buf, " \n\r\t"); // Get the begin

//		if (MIME_DNORMAL) fprintf(stdout,"MIME_is_uuencode_header: BEGIN = %s\n",bp);

		if (bp) fp = XAM_strtok(&tx, NULL, " \n\r\t"); // Get the file-permissions

		if (fp)
		{
			if (MIME_DNORMAL) fprintf(stdout,"MIME_is_uuencode_header: PERMISSIONS = %s\n",fp);

			if ((atoi(fp) == 0)||(atoi(fp) > 777))   // Maximum is 777, because R+W+X = 7
			{
				result = 0;
			}
			else result = 1;

		} else if (MIME_DNORMAL) fprintf(stdout,"MIME_is_uuencode_header: Cannot read permissions\n");
	}

//	if (MIME_DNORMAL) fprintf(stdout,"MIME_is_uuencode_header: RESULT = %d\n",result);

	return result;
}





/*------------------------------------------------------------------------
Procedure:     MIME_is_file_uuenc ID:1
Purpose:       Tries to determine if a given file is UUEncoded, or at
least contains a UUENCODED file to it.
This should only be run -after- we've checked with
is_file_mime() because if the file is MIME, then it'll be able
to detect UUencoding within the normal decoding routines.
Input:         filename to test
Output:        0 = not uuencoded
1 = _probably_ uuencoded.
Errors:
------------------------------------------------------------------------*/
int MIME_is_file_uuenc( char *fname )
{
	int result = 0;
	int linecount = 0;
	int limit=20;
	char *line;
	FILE *f;

	f = fopen(fname,"r");
	if (!f)
	{
		syslog(1,"MIME_is_file_mime: Error, cannot open file '%s' for reading (%s)",fname,strerror(errno));
		return -1;
	}

	line = malloc(sizeof(char) *1025);
	if (!line)
	{
		syslog(1,"MIME_is_file_mime: Error, cannot allocate memory for read buffer");
		return -1;
	}

	while ((linecount < limit)&&(fgets(line,1024,f)))
	{
		if (MIME_DNORMAL) fprintf(stdout,"MIME_is_file_uuenc: Testing line '%s'\n",line);
		if (MIME_is_uuencode_header( line ))
		{
			result = 1;
			break;
		}
		linecount++;
	}

	fclose(f);

	if (line) free(line);

	return result;
}


/*------------------------------------------------------------------------
Procedure:     MIME_decode_uu ID:1
Purpose:       Decodes a UUencoded stream
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_decode_uu( FFGET_FILE *f, char *unpackdir, struct _header_info *hinfo, int keep )
{
	int filename_found = 0;
	char buf[1024];
	char *bp = buf, *fn, *fp;
	int n, i, expected;
	char fullpath[1024]="";
	struct _txstrtok tx;
	unsigned char *writebuffer = NULL;
	unsigned char *wbpos;
	int wbcount = 0;
	int loop = 0;
	int buflen = 0;
 	FFGET_FILE ffinf;	// Local static FFGET struct used if *f is  NULL
	FFGET_FILE *finf;	// Points to either *f or &ffinf
	FILE *outf;
	int outfo =0; 			// set if outfile was opened.
	FILE *inf = NULL;

	// generate the filename, and open it up...

	if (MIME_DNORMAL) fprintf(stdout, "MIME_decode_uu: Starting.(%s) [FILE=%p HeaderInfo=%p]\n", hinfo->filename, f, hinfo );

	// If no FFGET_FILE param is passed to us directly, then we must create out own.

	if (!f)
	{
		if (MIME_DNORMAL) fprintf(stdout, "MIME_decode_uu: NULL FFGET stream given to us, create our own.\n");

		snprintf(fullpath,sizeof(fullpath),"%s/%s",unpackdir,hinfo->filename);

		inf = fopen(fullpath,"r");
		if (!inf)
		{
			if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_uu: Cannot open file '%s' (%s)",fullpath, strerror(errno));
			if (syslogging > 0) syslog(_SL,"MIME_decode_uu: Cannot open file '%s' (%s)",fullpath,strerror(errno));
			if (stderrlogging > 0) fprintf(stderr,"MIME_decode_uu: Cannot open file '%s' (%s)",fullpath,strerror(errno));
			return -1;
		}

		FFGET_setstream(&ffinf, inf);
		finf = &ffinf;

		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_uu: Creation done. [FFGET-FILE=%p, FILE=%p]\n", finf, inf);
	}
	else finf = f;

	writebuffer = malloc( _MIME_WRITE_BUFFER_SIZE *sizeof(unsigned char));
	if (!writebuffer)
	{
		if (syslogging > 0) syslog(_SL,"MIME_decode_64: Error: cannot allocate 100K of memory for the write buffer");
		if (stderrlogging > 0) fprintf(stderr,"MIME_decode_64: Error: cannot allocate 100K of memory for the write buffer");
		return -1;
	}
	else {
		wbpos = writebuffer;
		wbcount = 0;
	}


	if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_uu: Beginning.(%s)\n",fullpath);


	while (!FFGET_feof(finf))
	{
		filename_found = 0;

		// First lets locate the BEGIN line of this UUDECODE file

		while (FFGET_fgets(buf, sizeof(buf), finf))
		{

			if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_uu: Reading: %s\n",buf);


			if (strncasecmp(buf,"begin",5)==0)
			{
				if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_uu: Located BEGIN\n");
				// Okay, so the line contains begin at the start, now, lets get the decode details
				fp = fn = NULL;

				bp = XAM_strtok(&tx, buf, " \n\r\t"); // Get the begin

				if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_uu: BEGIN = '%s'\n",bp);
				if (bp) fp = XAM_strtok(&tx, NULL, " \n\r\t"); // Get the file-permissions

				if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_uu: Permissions/Name = '%s'\n",fp);
				if (fp) fn = XAM_strtok(&tx, NULL, "\n\r"); // Get the file-name

				if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_uu: Name = '%s'\n",fn);

				if (!fn)
				{
					bp = fp;
				}
				else bp = fn;

				if ((!bp)&&(!f))
				{
					fprintf(stderr,"MIME_decode_uu: WARNING - unable to obtain filename from UUencoded text file header");
					if (writebuffer) free(writebuffer);
					fclose(inf);
					return -1;
				}

				if (MIME_DNORMAL) fprintf(stdout,"%s:%d:MIME_decode_uu: Full path = (%s)\n",__FILE__,__LINE__,bp);

				filename_found = 1;
				break;
			} // If line starts with BEGIN


		} // While more lines in the INPUT file.


		if ((filename_found)&&(bp))
		{
			if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_uu: Located filename (%s), now decoding.\n",bp);

			// Clean up the file name
			snprintf(hinfo->uudec_name, 128, "%s", bp); // FIXME - replace 128 with real value.

			MIME_clean_MIME_filename( bp, _MIME_STRLEN_MAX );
			quick_clean_filename( bp, _MIME_STRLEN_MAX );

			// Create the new output full path

			snprintf(fullpath, sizeof(fullpath), "%s/%s",unpackdir,bp);
			if (MIME_DNORMAL) fprintf(stdout,"%s:%d:MIME_decode_uu: Filename = (%s)\n",__FILE__,__LINE__,fullpath);

			outf = fopen(fullpath, "wb");
			if (!outf)
			{
				if (syslogging > 0) syslog(_SL,"MIME_decode_uu: Cannot open file '%s' (%s)",fullpath,strerror(errno));
				if (stderrlogging > 0) fprintf(stderr,"MIME_decode_uu: Cannot open file '%s' (%s)",fullpath,strerror(errno));
				if (writebuffer) free(writebuffer);
				return -1;
			} else outfo = 1;

	// Allocate the write buffer.  By using the write buffer we gain an additional 10% in performance
	// due to the lack of function call (fwrite) overheads

			// Okay, now we have the UUDECODE data to decode...

			wbcount = 0;
			wbpos = writebuffer;

			while (outf)
			{
				// for each input line
				if (FFGET_fgets(buf, sizeof(buf), finf) == NULL)
				{
					fprintf(stderr,"MIME_decode_uu: Short file\n");
					return -1;
				}

				// If we've reached the end of the UUencoding

				if (strncasecmp(buf,"end",3)==0)
				{
					if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_uu: End of UUencoding detected\n");
					break;
				}

				if ( !strpbrk(buf,"\r\n") )
				{
					fprintf(stdout,"MIME_decode_uu: WARNING - Excessive length line\n");
				}

				// The first char of the line indicates how many bytes are to be expected

				n = uudec[(int)*buf];


				// If the line is a -blank- then break out.

				if ((n <= 0) || (*buf == '\n')) break;

				// Calculate expected # of chars and pad if necessary

				expected = ((n+2)/3)<<2;
				buflen = strlen(buf) -1;
				for (i = buflen; i <= expected; i++) buf[i] = ' ';
				bp = &buf[1];

				// Decode input buffer to output file.

				while (n > 0)
				{
					// In order to reduce function call overheads, we've bought the UUDecoding
					// bit shifting routines into the UUDecode main decoding routines. This should
					// save us about 250,000 function calls per Mb.
					// MIME_outdec(bp, outf, n);

					char c[3];
					int m = n;

					c[0] = uudec[(int)*bp] << 2 | uudec[(int)*(bp+1)] >> 4;
					c[1] = uudec[(int)*(bp+1)] << 4 | uudec[(int)*(bp+2)] >> 2;
					c[2] = uudec[(int)*(bp+2)] << 6 | uudec[(int)*(bp+3)];

					if (m > 3) m = 3;

					if ( wbcount >= _MIME_WRITE_BUFFER_LIMIT )
					{
						fwrite(writebuffer, 1, wbcount, outf);
						wbpos = writebuffer;
						wbcount = 0;
					}

					// Transfer the decoded data to the write buffer.
					// The reason why we use a loop, rather than just a set of if
					// statements is just for code-viewing simplicity.  It's a lot
					// easier to read than some nested chain of if's

					for (loop = 0; loop < m; loop++)
					{
						*wbpos = c[loop];
						wbpos++;
						wbcount++;
					}

					bp += 4;
					n -= 3;

				} // while (n > 0)

			} // While (1)

			if ((outfo)&&(wbcount > 0))
			{
				fwrite(writebuffer, 1, wbcount, outf);
			}


			if (outfo) fclose(outf);
			if (_verbosity) fprintf(stdout,"Decoded %s\n",fullpath);

			// Increment the Attachment Counter

			_attachment_count++;

		} // If valid filename was found for UUdecode
		else
		{
			hinfo->uudec_name[0] = '\0';
			if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_uu: No FILENAME was found in data...\n");
		}

		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_uu: Segment completed\n");

		// If this file was a result of the x-uuencode content encoding, then we need to exit out
		// as we're reading in the -stream-, and we dont want to carry on reading because we'll
		// end up just absorbing email data which we weren't supposed to.

		if ((f)&&(hinfo->content_transfer_encoding == _CTRANS_ENCODING_UUENCODE)) break;

	} // While !feof(inf)



	if (writebuffer) free(writebuffer);

// if (MIME_DNORMAL) if (FFGET_feof(finf)) fprintf(stdout,"MIME_decode_uu: End of input file hit\n");

	if (MIME_DNORMAL) fprintf(stdout, "MIME_decode_uu: Completed\n");

	if (inf) fclose(inf);

	if (MIME_DNORMAL) fprintf(stdout, "MIME_decode_uu: Exiting.[FILE=%p HeaderInfo=%p]\n", f, hinfo );

	return 0;
}




/*------------------------------------------------------------------------
Procedure:     MIME_decode_text_line ID:1
Purpose:       Decodes a line of text, checking for QuotePrintable characters
and converting them.  Note - if the character converted is a \0
(after decoding) it shouldn't affect the calling parent because the
calling parent should read back the returned string byte size and
use fwrite() or other non-\0 affected writing/processing functions
Input:         char *line: pointer to the buffer/line we wish to convert/scan
Output:        int: size of final buffer in bytes.
Errors:
------------------------------------------------------------------------*/
int MIME_decode_text_line( char *line )
{

	char c;								/* The Character to output */
	int op, ip; 						/* OutputPointer and InputPointer */
	int slen = strlen(line); /* Length of our line */

//	if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_text_line: Input length = %d\n",slen);

	/* Initialise our "pointers" to the start of the encoded string */
	ip=op=0;

	/* for every character in the string... */
	for (ip = 0; ip < slen; ip++)
	{

		c = line[ip];

		/* if we have the quote-printable esc char, then lets get cracking */
		if (c == '=')
		{

			/* if we have another two chars... */
			if (ip <= (slen-2))
			{

				/* convert our encoded character from HEX -> decimal */
				c = (char)hexconv[(int)line[ip+1]]*16 +hexconv[(int)line[ip+2]];

				/* shuffle the pointer up two spaces */
				ip+=2;
			} /* if there were two extra chars after the ='s */

			/* if we didn't have enough characters, then  we'll make the char the
			* string terminator (such as what happens when we get a =\n
			*/
			else
			    {
				line[ip] = '\0';
			} /* else */

		} /* if c was a encoding char */

		/* put in the new character, be it converted or not */
		line[op] = c;

		/* shuffle up the output line pointer */
		op++;
	} /* for */

	/* terminate the line */
	line[op]='\0';

//	if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_text_line: Output length = %d\n",strlen(line));

	return (op-1);

}




/*------------------------------------------------------------------------
Procedure:     MIME_decode_TNEF ID:1
Purpose:       Decodes TNEF encoded attachments
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_decode_TNEF( char *unpackdir, struct _header_info *hinfo, int keep )
{
	int result=0;
	char fullpath[1024];

	snprintf(fullpath,sizeof(fullpath),"%s/%s",unpackdir,hinfo->filename);

	TNEF_set_path(unpackdir);

	result = TNEF_main( fullpath );

	if (result >= 0)
	{
		//		result = remove( fullpath );
		if (result == -1)
		{
			if (_verbosity) fprintf(stderr,"MIME_decode_TNEF: Removing %s failed (%s)",fullpath,strerror(errno));
		}
	}

	return result;
}




/*------------------------------------------------------------------------
Procedure:     MIME_decode_raw ID:1
Purpose:       Decodes a binary type attachment, ie, no encoding, just raw data.
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_decode_raw( FFGET_FILE *f, char *unpackdir, struct _header_info *hinfo, int keep )
{
	int result = 0;
	char fullpath[1024];
	int bufsize=1024;
	char *buffer = malloc((bufsize +1)*sizeof(char));
	int readcount;
	int file_has_uuencode = 0;
	FILE *fo;

	/* Decoding / reading a binary attachment is a real interesting situation, as we
	* still use the fgets() call, but we do so repeatedly until it returns a line with a
	* \n\r and the boundary specifier in it.... all in all, I wouldn't rate this code
	* as being perfect, it's activated only if the user intentionally specifies it with
	* --binary flag
	*/

	if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_raw: Start\n");

	snprintf(fullpath,sizeof(fullpath),"%s/%s",unpackdir,hinfo->filename);
	fo = fopen(fullpath,"wb");

	if (!fo)
	{
		if (stderrlogging) fprintf(stderr,"MIME_decode_raw: Error, cannot open file %s for writing. (%s)\n\n",fullpath,strerror(errno));
		if (syslogging) syslog(_SL,"MIME_decode_raw: Error, cannot open file %s for writing. (%s)\n\n",fullpath,strerror(errno));
		return -1;
	}

	while ((readcount=FFGET_raw(f, buffer,bufsize)) > 0)
	{
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_raw: BUFFER[%p]= '%s'\n",buffer, buffer);

		if ((!file_has_uuencode)&&(MIME_is_uuencode_header( buffer )))
		{
			if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_raw: UUENCODED is YES (buffer=[%p]\n",buffer);

			if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_raw: File contains UUENCODED data(%s)\n",buffer);

			file_has_uuencode = 1;
		}

		if (MIME_BS_cmp(buffer, readcount))
		{
			if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_raw: Boundary located - breaking out.\n");

			break;
		}
		else
		    {
		if (MIME_DNORMAL) fprintf(stdout,".,\n");

			fwrite(buffer,sizeof(char),readcount,fo);
		}
	}

	if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_raw: Completed reading RAW data\n");

	free(buffer);
	fclose(fo);

	if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_raw: Closed file and free'd buffer\n");

	// If there was UUEncoded portions [potentially] in the email, the
	// try to extract them using the MIME_decode_uu()
	//
	if (file_has_uuencode)
	{
		if (MIME_DNORMAL) fprintf(stdout,"Decoding UUencoded data\n");
		result = MIME_decode_uu(NULL, unpackdir, hinfo, keep );
		if (strlen(hinfo->uudec_name))
		{
			if (strcasecmp(hinfo->uudec_name,"winmail.dat")==0)
			{
				fprintf(stdout,"Decoding TNEF format\n");
				snprintf(hinfo->filename, 128, "%s", hinfo->uudec_name);
				MIME_decode_TNEF( unpackdir, hinfo, keep);
			} else fprintf(stdout,"MIME_decode_raw: hinfo has been clobbered.\n");
		}
	}

	if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_raw: End[%d]\n",result);

	return result;
}



/*------------------------------------------------------------------------
Procedure:     MIME_decode_text ID:1
Purpose:       Decodes an input stream into a text file.
Input:         unpackdir : directory where to place new text file
hinfo : struct containing information from the last parsed headers
keep : if set, retain the file
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_decode_text( FFGET_FILE *f, char *unpackdir, struct _header_info *hinfo, int keep )
{

	FILE *of; 							// output file
	int linecount = 0;  				// The number of lines
	int file_has_uuencode = 0;			// Flag to indicate this text has UUENCODE in it
	char fullfilename[1024]=""; 	// Filename of the output file
	char line[1024]; 					// The input lines from the file we're decoding
	char *get_result = &line[0];
	int lastlinewasboundary = 0;
	int result = 0;
	int decodesize=0;

	snprintf(fullfilename,sizeof(fullfilename),"%s/%s",unpackdir,hinfo->filename);

	if (MIME_DNORMAL) fprintf(stdout,"Decoding Print Quotable to %s\n",fullfilename);

	if (!f)
	{
		if (syslogging > 0) syslog(_SL,"Error: ripMIME print-quotable input stream broken.");
		if (stderrlogging > 0) fprintf(stderr,"Error: ripMIME print-quotable input stream broken.");
		//exit(_EXITERR_PRINT_QUOTABLE_INPUT_NOT_OPEN);
		return -1;
	}

	// if our FILE stream is open
	if (f)
	{

		of = fopen(fullfilename,"w");
		if (!of)
		{
			if (syslogging > 0) syslog(_SL,"Error: cannot open %s for writing",fullfilename);
			if (stderrlogging > 0) fprintf(stderr,"Error: cannot open %s for writing",fullfilename);
			//			exit(_EXITERR_PRINT_QUOTABLE_OUTPUT_NOT_OPEN);
			return -1;
		}

		while ((get_result = FFGET_fgets(line,1023,f))&&(of))
		{
//			if (MIME_DPEDANTIC) fprintf(stdout,"DEBUG:%d: %s",__LINE__,line); // DEBUG

			if ((hinfo->boundary[0] != '\0')&&(MIME_BS_cmp(line,sizeof(line)-1)))
			{
				lastlinewasboundary = 1;
				result = 0;
				break;
			}


			if (lastlinewasboundary == 0)
			{
				if (hinfo->content_transfer_encoding == _CTRANS_ENCODING_QP)
				{
					decodesize = MIME_decode_text_line(line);

//					if (MIME_DNORMAL) fprintf(stdout,"DEBUG:%d:%s\\\n",__LINE__,line); // DEBUG

					fwrite(line, 1, decodesize, of);

//					fprintf(of,"%s",line);	//QP decode can result in \0 bytes, so, fprintf is rendered
//					useless, hence we're now using fwrite().
//					CONTRIBUTED by Chea Chee Keong  <cheekeong@transparity.com> (and other TNEF routines)
																								}
				else fprintf(of,"%s",line);


				if ((!file_has_uuencode)&&(MIME_is_uuencode_header( line )))
				{
					if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_text: UUENCODED data located in file.\n");
					file_has_uuencode = 1;
				}
			}
			linecount++;

		} // while

		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_text: Done writing output file...now attempting to close.");



		// if the file is still safely open
		if (of)
		{

			// close it
			fclose(of);
			// if we wrote nothing, then trash the file
			if ((keep == 0)||(linecount == 0))
			{
				if (MIME_DNORMAL) fprintf(stdout,"Removing saved attachment (keep=%d, linecount=%d)\n",keep,linecount);
				unlink(fullfilename);
			}
		} // if file still safely open

		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_text: Closed.");

	} // if main input file stream was open


	// If our input from the file was invalid due to EOF or other
	// then we return a -1 code to indicate that the end has
	// occured.
	//
	if (!get_result) result = -1;

	// If there was UUEncoded portions [potentially] in the email, the
	// try to extract them using the MIME_decode_uu()
	//
	if (file_has_uuencode)
	{
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_text: Decoding UUencoded data\n");

		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_text: hinfo = %p\n", hinfo);
		result = MIME_decode_uu( NULL, unpackdir, hinfo, keep );
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_text: hinfo = %p\n", hinfo);

		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_text: Done. [ UUName = '%s' ]\n", hinfo->uudec_name);

		if (strncasecmp(hinfo->uudec_name,"winmail.dat",11)==0)
		{
			fprintf(stdout,"Decoding TNEF format\n");
			snprintf(hinfo->filename, 128, "%s", hinfo->uudec_name);
			MIME_decode_TNEF( unpackdir, hinfo, keep );
		}

		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_text: Completed decoding UUencoded data.\n");
	}

	if (MIME_DNORMAL) fprintf(stdout,"-----------------Done\n");

	return result;
}




/*------------------------------------------------------------------------
Procedure:     MIME_decode_64 ID:1
Purpose:       This routine is very very very important, it's the key to ensuring
we get our attachments out of the email file without trauma!
NOTE - this has been -slightly altered- in order to make provision
of the fact that the attachment may end BEFORE the EOF is received
as is the case with multiple attachments in email.  Hence, we
now have to detect the start character of the "boundary" marker
I may consider testing the 1st n' chars of the boundary marker
just incase it's not always a hypen '-'.
Input:         FGET_FILE *f: stream we're reading from
char *unpackdir: directory we have to write the file to
struct _header_info *hinfo: Auxillairy information such as the destination filename
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_decode_64( FFGET_FILE *f, char *unpackdir, struct _header_info *hinfo )
{

	int i;
	int cr_count = 0; /* the number of consecutive \n's we've read in, used to detect End of B64 enc */
	int stopcount = 0; /* How many stop (=) characters we've read in */
	int eom_reached = 0; /* flag to say that we've reached the End-Of-MIME encoding. */
	int status = 0; /* Overall status of decoding operation */
	int c; /* a single char as retrieved using MIME_get_char() */
	int char_count = 0; /* How many chars have been received */
	int boundary_crash = 0; /* if we crash into a boundary, set this */
	long int bytecount=0; /* The total file decoded size */
	char output[3]; /* The 4->3 byte output array */
	char input[4]; /* The 4->3 byte input array */
	char fullMIME_filename[_MIME_STRLEN_MAX]=""; /* Full Filename of output file */

	// Write Buffer routine

	unsigned char *writebuffer;
	unsigned char *wbpos;
	int wbcount = 0;
	int loop;

	FILE *of; /* output file pointer */

	/* generate the MIME_filename, and open it up... */
	if (_unique_names) MIME_test_uniquename( unpackdir, hinfo->filename, _rename_method );
	snprintf(fullMIME_filename,_MIME_STRLEN_MAX,"%s/%s",unpackdir,hinfo->filename);
	of = fopen(fullMIME_filename,"wb");


	/* if we were unable to open the output file, then we better log an error and drop out */
	if (!of)
	{
		if (syslogging > 0) syslog(_SL,"Error: Cannot open output file %s for BASE64 decoding.",fullMIME_filename);
		if (stderrlogging > 0) fprintf(stderr,"Error: Cannot open output file %s for BASE64 decoding.",fullMIME_filename);
		//		exit(_EXITERR_BASE64_OUTPUT_NOT_OPEN);
		return -1;
	}


	// Allocate the write buffer.  By using the write buffer we gain an additional 10% in performance
	// due to the lack of function call (fwrite) overheads

	writebuffer = malloc( _MIME_WRITE_BUFFER_SIZE *sizeof(unsigned char));
	if (!writebuffer)
	{
		if (syslogging > 0) syslog(_SL,"MIME_decode_64: Error: cannot allocate 100K of memory for the write buffer");
		if (stderrlogging > 0) fprintf(stderr,"MIME_decode_64: Error: cannot allocate 100K of memory for the write buffer");
		return -1;
	}
	else {
		wbpos = writebuffer;
		wbcount = 0;
	}



	/* collect prefixing trash (if any, such as spaces, CR's etc)*/
	c = MIME_getchar_start(f);

	/* and push the good char back */
	FFGET_ungetc(f,c);


	/* do an endless loop, as we're -breaking- out later */
	while (1)
	{

		/* Initialise the decode buffer */
		input[0] = input[1] = input[2] = input[3] = '0';

		/* snatch 4 characters from the input */
		for (i = 0; i < 4; i++)
		{

			// Get Next char from the file input
			//
			// A lot of CPU is wasted here due to function call overheads, unfortunately
			// I cannot yet work out how to make this call (FFGET) operate effectively
			// without including a couple of dozen lines in this section.
			//
			// Times like this C++'s "inline" statement would be nice.
			//

			do {
				if (f->ungetcset)
				{
					f->ungetcset = 0;
					c = f->c;
				}
				else
				    {
					if ((!f->startpoint)||(f->startpoint > f->endpoint))
					{
						FFGET_getnewblock(f);
					}

					if (f->startpoint <= f->endpoint)
					{
						c = *f->startpoint;
						f->startpoint++;
					}
					else
					{
						c = EOF;
					}
				}


																		}
			while ( (c != EOF) && ( c < ' ' ) && ( c != '\n' ) && (c != '-') );

			// if we get a CR then we need to check a few things...

			if (c == '\n')
			{
				cr_count++;
				if (cr_count > 1)
				{
					if (MIME_DNORMAL) fprintf(stdout,"EOF Reached due to two consecutive CR's\n");
					eom_reached++;
					break;
				}
				else
				    {
					char_count = 0;
					i--;
					continue;
				} // else if it wasn't our 2nd CR

			}
			else
			    {
				cr_count=0;
			}



			/* if we get an EOF char, then we know something went wrong */
			if ( c == EOF )
			{
//				if (syslogging > 0) syslog(_SL, "Error: input stream broken for base64 decoding for file %s\n",hinfo->filename);
//				if (MIME_DNORMAL) fprintf(stderr,"Error: input stream broken for base64 decoding for file %s\n",hinfo->filename);
				status = -1;
				fwrite(writebuffer, 1, wbcount, of);
				fclose(of);
				if (writebuffer) free(writebuffer);
				return status;
				break;
			} /* if c was the EOF */
			else
			    if (c == '=')
			{
				// Once we've found a stop char, we can actually just "pad" in the rest
				// of the stop chars because we know we're at the end. Some MTA's dont
				// put in enough stopchars... at least it seems X-MIMEOLE: Produced By Microsoft MimeOLE V5.50.4133.2400
				// doesnt.

				if (i == 2)
				{
					input[2] = input[3] = (char)b64[c];
				}
				else if (i == 3)
				{
					input[3] = (char)b64[c];
				}

				// Some Microsoft mail generators dont put in sufficient number of = symbols
				// to pad the file out to a multiple of 4 chars. Hence, in order to prevent
				// an over-read, we stop once we detect the first one.

				// NOTE------
				// Previously we relied on the fact that if we detected a stop char, that FFGET()
				// would automatically absorb the data till EOL. This is no longer the case as we
				// are now only retrieving data byte at a time.
				// So, now we -absorb- till the end of the line using FFGET_fgets()

				stopcount = 4 -i;
				FFGET_fgets(scratch,sizeof(scratch),f);
				if (MIME_DNORMAL) fprintf(stdout,"Stop char detected pos=%d...StopCount = %d\n",i,stopcount);
				i = 4;



				break; // out of FOR.

			}
			else
			    if (c == '-' )
			{
				if (FFGET_fgetc(f) == '-')
				{
					boundary_crash++;
					eom_reached++;
					break;
				}
			}


			/* test for and discard invalid chars */
			if (b64[c] == 0x80)
			{
				i--;
				continue;
			}

			/* do the conversion from encoded -> decoded */

			input[i] = (char)b64[c];

			/* assuming we've gotten this far, then we increment the char_count */
			char_count++;

		} // FOR


		// now that our 4-char buffer is full, we can do some fancy bit-shifting and get the required 3-chars of 8-bit data

		output[0] = (input[0] << 2) | (input[1] >> 4);
		output[1] = (input[1] << 4) | (input[2] >> 2);
		output[2] = (input[2] << 6) | input[3];

		// determine how many chars to write write and check for errors if our input char count was 4 then we did receive a propper 4:3 Base64 block, hence write it

		if (i == 4)
		{
			if ( wbcount > _MIME_WRITE_BUFFER_LIMIT )
			{
				fwrite(writebuffer, 1, wbcount, of);
				wbpos = writebuffer;
				wbcount = 0;
			}

			for (loop = 0; loop < (3 -stopcount); loop++)
			{
				*wbpos = output[loop];
				wbpos++;
				wbcount++;
			}

			// tally up our total byte conversion count

			bytecount+=(3 -stopcount);

		}
		else if (MIME_DNORMAL) fprintf(stdout,"ERROR - could not attain 4 bytes input\n");


		/* if we wrote less than 3 chars, it means we were at the end of the encoded file thus we exit */
		if ((eom_reached)||(stopcount > 0)||(boundary_crash)||(i!=4))
		{

			if (wbcount > 0)
			{
				fwrite(writebuffer, 1, wbcount, of);
			}

			/* close the output file, we're done writing to it */
			fclose(of);

			/* if we didn't really write anything, then trash the  file */
			if (bytecount == 0)
			{
				unlink(fullMIME_filename);
			}

			if (boundary_crash) status = 1; // was _BOUNDARY_CRASH

			if (MIME_DNORMAL) fprintf(stdout,"File size = %ld bytes, Exit Status = %d, Boundary Crash = %d\n",bytecount, status, boundary_crash);

			if (writebuffer) free(writebuffer);

			return status;

		} /* if End-of-MIME or Stopchars appeared */

	} /* while */

	if (writebuffer) free(writebuffer);

	return status;

}





/*------------------------------------------------------------------------
Procedure:     MIME_doubleCR_decode ID:1
Purpose:       Decodes a text sequence as detected in the processing of the MIME headers.
This is a specialised call, not really a normal part of MIME decoding, but is
required in order to deal with decyphering MS Outlook visable defects.
Input:         char *filename: Name of the encoded file we need to decode
char *unpackdir: Directory we need to unpack the file to
struct _header_info *hinfo: Header information already gleaned from the headers
int current_recursion_level: How many nest levels we are deep
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_doubleCR_decode( char *filename, char *unpackdir, struct _header_info *hinfo, int current_recursion_level )
{
	int result = 0;
	struct _header_info h;
	char *p;

	if ((p=strrchr(filename,'/'))) p++;
	else p = filename;

	memcpy(&h, hinfo, sizeof(h));
// Works for ripMIME	snprintf(h.filename, sizeof(h.filename), "%s/%s", unpackdir, p);
	snprintf(h.filename, sizeof(h.filename), "%s", p); /// Works for Xamime
	if (MIME_is_file_mime(filename))
	{
		if (_verbosity) fprintf(stdout,"Attempting to decode MIME attachment '%s'\n",filename);
		MIME_unpack( unpackdir, filename, current_recursion_level +1);
	}
	else if (MIME_is_file_uuenc(h.filename))
	{
		if (_verbosity) fprintf(stdout,"Attempting to decode UUENCODED attachment '%s'\n",filename);
		MIME_decode_uu( NULL, unpackdir, &h, 1 );
	}

	return result;
}






/*------------------------------------------------------------------------
Procedure:     MIME_read ID:1
Purpose:       Reads data from STDIN and saves the mailpack to the filename
specified
Input:         char *mpname: full pathname of the file to save the data from STDIN
to
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_read( char *mpname )
{

	int c;
	long int fsize=-1;

	/* open up our input file */
	FILE *fout = fopen(mpname,"w");


	/* check that out file opened up okay */
	if (!fout)
	{
		if (syslogging > 0) syslog(_SL,"Error: Cannot open file %s for writing... check permissions perhaps?",mpname);
		if (stderrlogging > 0) fprintf(stderr,"Error: Cannot open file %s for writing... check permissions perhaps?",mpname);
		//exit(_EXITERR_MIMEREAD_CANNOT_OPEN_OUTPUT);
		return -1;
	}

	/* assuming our file actually opened up */
	if (fout)
	{

		fsize=0;

		/* while there is more data, consume it */
		while ((c = getc(stdin)) != EOF)
		{

			/* write it to file */
			if (fputc(c,fout) != EOF)
			{
				fsize++;
			}
			else
			    {
				if (syslogging > 0) syslog(_SL,"Error: Cannot write to file %s... maybe you are out of space?", mpname);
				if (stderrlogging > 0) fprintf(stderr,"Error: Cannot write to file %s... maybe you are out of space?",mpname);
				//exit(_EXITERR_MIMEREAD_CANNOT_WRITE_OUTPUT);
				return -1;
			}
		}

		/* clean up our buffers and close */
		fflush(fout);
		fclose(fout);

	} /* end if fout was received okay */

	/* return our byte count in KB */
	return (int)(fsize /1024);
}



/*------------------------------------------------------------------------
Procedure:     MIME_init_hexconv ID:1
Purpose:       Initialise the array which will be used to convert Hexadecimal sequences to decimal
Input:         none
Output:
Errors:        DEPRECATED
------------------------------------------------------------------------*/
int MIME_init_hexconv( void )
{

	/*
	hexconv['0'] = 0;
	hexconv['1'] = 1;
	hexconv['2'] = 2;
	hexconv['3'] = 3;
	hexconv['4'] = 4;
	hexconv['5'] = 5;
	hexconv['6'] = 6;
	hexconv['7'] = 7;
	hexconv['8'] = 8;
	hexconv['9'] = 9;
	hexconv['a'] = 10;
	hexconv['b'] = 11;
	hexconv['c'] = 12;
	hexconv['d'] = 13;
	hexconv['e'] = 14;
	hexconv['f'] = 15;
	hexconv['A'] = 10;
	hexconv['B'] = 11;
	hexconv['C'] = 12;
	hexconv['D'] = 13;
	hexconv['E'] = 14;
	hexconv['F'] = 15;
	*/
	syslog(1,"MIME_init_hexconv(): WARNING - Using a deprecated function. Please remove from your code.");

	return 0;
}


/*------------------------------------------------------------------------
Procedure:     MIME_init ID:1
Purpose:       Initialise various required parameters to ensure a clean starting of
MIME decoding.
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_init( void )
{

	_attachment_count = 0;
	_current_line = 0;
	return 0;
}




/*------------------------------------------------------------------------
Procedure:     MIME_decode_encoding ID:1
Purpose:       Based on the contents of hinfo, this function will call the
required function needed to decode the contents of the file
which is contained within the MIME structure
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_decode_encoding( FFGET_FILE *f, char *unpackdir, struct _header_info *hinfo )
{
	int keep = 1;
	int result = -1;

	if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_encoding: Start: (%s)\n",hinfo->filename);

	// If we have a valid filename, then put it through the process of
	// 	cleaning and filtering
	//
	if (isprint(hinfo->filename[0]))
	{
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_encoding: Filename is valid, cleaning\n");

		MIME_clean_MIME_filename(hinfo->filename, _MIMEH_FILENAMELEN_MAX);	/* check out thefilename for ISO filenames */
		if (MIME_DNORMAL) { fprintf(stdout,"MIME_decode_encoding: Cleaned filename Stage 1.\n"); fflush(stdout); }
		quick_clean_filename(hinfo->filename, _MIMEH_FILENAMELEN_MAX); 	/* cleanup garbage characters */
		if (MIME_DNORMAL) { fprintf(stdout,"MIME_decode_encoding: Cleaned filename Stage 2.\n"); fflush(stdout); }


	}

	// If the filename is NOT valid [doesn't have a printable first char]
	// 	then we must create a new file name for it.
	//
	if (!isprint(hinfo->filename[0]))
	{
		sprintf(hinfo->filename,"%s%d",blankfileprefix,filecount);
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_encoding: Filename is not valid, setting to default...(%s)\n",hinfo->filename);
		filecount++;
		if (_no_nameless) keep = 0;
	}
	else
	    if (strncmp(hinfo->filename,blankfileprefix,strlen(blankfileprefix)) != 0)
	{
		_attachment_count++;
	}

	// If we are required to have "unique" filenames for everything, rather than
	// 	allowing ripMIME to overwrite stuff, then we put the filename through
	//		its tests here
	//
	if ((_unique_names)&&(keep)) MIME_test_uniquename( unpackdir, hinfo->filename, _rename_method );

	// If the calling program requested verbosity, then indicate that we're decoding
	//		the file here
	//
	if ((keep)&&(_verbosity)) fprintf(stdout,"Decoding %s\n", hinfo->filename);


	// Select the decoding method based on the content transfer encoding
	// 	method which we read from the headers
	//

	if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_encoding: ENCODING = %d\n",hinfo->content_transfer_encoding);

	switch (hinfo->content_transfer_encoding)
	{
	case _CTRANS_ENCODING_B64:
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_encoding: Decoding BASE64 format\n");
		result = MIME_decode_64(f, unpackdir, hinfo);
		if (result == 1) result = 0;  // If we get a boundary crash, ignore it.
		break;
	case _CTRANS_ENCODING_7BIT:
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_encoding: Decoding 7BIT format\n");
		result = MIME_decode_text(f, unpackdir, hinfo, keep);
		break;
	case _CTRANS_ENCODING_8BIT:
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_encoding: Decoding 8BIT format\n");
		result = MIME_decode_text(f, unpackdir, hinfo, keep);
		break;
	case _CTRANS_ENCODING_RAW:
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_encoding: Decoding RAW format\n");
		result = MIME_decode_raw(f, unpackdir, hinfo, keep);
		break;
	case _CTRANS_ENCODING_QP:
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_encoding: Decoding QuotePrintable format\n");
		result = MIME_decode_text(f, unpackdir, hinfo, keep);
		break;
	case _CTRANS_ENCODING_UUENCODE:
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_encoding: Decoding UUENCODED format\n");
		result = MIME_decode_uu(f, unpackdir, hinfo, keep);
		break;
	case _CTRANS_ENCODING_UNKNOWN:
		result = MIME_decode_text(f, unpackdir, hinfo, keep);
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_encoding: UNKNOWN Decode completed\n");
		break;
	case _CTRANS_ENCODING_UNSPECIFIED:
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_encoding: Decoding UNSPECIFIED format\n");
		result = MIME_decode_text(f, unpackdir, hinfo, keep);
		break;
	default:
		if (MIME_DNORMAL) fprintf(stdout,"MIME_decode_encoding: Decoding format is not defined (%d)\n",hinfo->content_transfer_encoding);
		if (syslogging > 0) syslog(1,"MIME_decode_encoding: Unknown encoding %d",hinfo->content_transfer_encoding);
		result = MIME_decode_raw(f, unpackdir, hinfo, keep);
		break;
	}

	if ((result != -1)&&(hinfo->content_type == _CTYPE_TNEF))
	{
		if ((MIME_DNORMAL)||(_verbosity)) fprintf(stdout,"MIME_decode_encoding: Decoding TNEF format\n");
		_attachment_count++;
		MIME_decode_TNEF( unpackdir, hinfo, 0 );
	}

	// Look for Microsoft MHT files... and try decode them.
	//	MHT files are just embedded email files, except they're usually
	//	encoded as BASE64... so, you have to -unencode- them, to which
	//	you find out that lo, you have another email.

	if ( (result != -1) && ( (strstr(hinfo->filename,".mht"))||(strstr(hinfo->name,".mht"))) )
	{
		fprintf(stdout,"MIME_decode_encoding: Last filename was : %s\n",hinfo->name);
		snprintf(hinfo->scratch,sizeof(hinfo->scratch),"%s/%s",unpackdir,hinfo->name);
		MIME_unpack( unpackdir, hinfo->scratch, (hinfo->current_recursion_level+1) );
	}

	return result;
}




/*------------------------------------------------------------------------
Procedure:     MIME_unpack_stage2 ID:1
Purpose:       This function commenced with the file decoding of the attachments
as required by the MIME structure of the file.
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_unpack_stage2( FFGET_FILE *f, char *unpackdir, struct _header_info *hinfo, int current_recursion_level )
{
	int result = 0;
	struct _header_info *h;
	char *p;

	if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2: Start, recursion %d\n",current_recursion_level);

	if (current_recursion_level > _RECURSION_LEVEL_MAX)
	{
		if (syslogging > 0) syslog(_SL,"MIME_unpack_stage2(): Current Recursion level of %d is greater than permitted %d",current_recursion_level, _RECURSION_LEVEL_MAX);
		if (stderrlogging > 0) fprintf(stderr,"MIME_unpack_stage2(): Current Recursion level of %d is greater than permitted %d\n",current_recursion_level, _RECURSION_LEVEL_MAX);
		return -1;
	}

	h = hinfo;

	// Get our headers and determin what we have...
	//
	if (MIME_DNORMAL) fprintf(stdout,"%s:%d:Parsing headers (initial)\n",FL);

	// Parse the headers, extracting what information we need
	//
	result = MIMEH_parse_headers(f,h);

	if (MIME_DNORMAL) fprintf(stdout,"%s:%d:Headers parsed, Result = %d\n",FL,result);

	if (MIMEH_doubleCR)
	{
		MIME_doubleCR_decode(MIMEH_doubleCRname, unpackdir, h, current_recursion_level);
		MIMEH_doubleCR = 0;
		FFGET_SDL_MODE = 0;
	}

	// If we dont get what we expected, then jump out before
	// 	we push things too far and possibly cause a segfault
	//
	if (result == -1) return result;

	// If we located a boundary being specified (as apposed to existing)
	// then we push it to the BoundaryStack
	//

	if (h->boundary_located)
	{
		if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2:%s:%d:Boundary located, pushing to stack (%s)\n",FL,h->boundary);
		MIME_BS_push(h->boundary);
		h->boundary_located = 0;
	}
	else
	    {
		if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2:%s:%d:Decoding in BOUNDARY-LESS mode\n",FL);

		if ((h->content_type == _CTYPE_RFC822)||(h->content_type == _CTYPE_MULTIPART))
		{
			if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2:%s:%d:Decoding multipart/embedded message\n",FL);

			// If there is no filename, then we have a "standard"
			// embedded message, which can be just read off as a
			// continuous stream (simply with new boundaries
			//

			if (( h->content_transfer_encoding != _CTRANS_ENCODING_B64)&&( h->filename[0] == '\0' ))
			{
				if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2:%s:%d:Non base64 encoding AND no filename, embedded message\n",FL);

				h->boundary_located = 0;

				result = MIME_unpack_stage2(f, unpackdir, h, current_recursion_level +1);

				p = MIME_BS_top();
				if (p) zstrncpy(h->boundary, p,sizeof(h->boundary));
			}
			else
			    {
				if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2:%s:%d:embedded message has a filename, decoding to file %s",FL,h->filename);
				result = MIME_decode_encoding( f, unpackdir, h );

								// Because we're calling MIME_unpack_single again [ie, recursively calling it
								// we need to now adjust the input-filename so that it correctly is prefixed
								// with the directory we unpacked to.

								snprintf(scratch,sizeof(scratch),"%s/%s",unpackdir, h->filename);
								snprintf(h->filename,sizeof(h->filename),"%s",scratch);
				result = MIME_unpack_single( unpackdir, h->filename, current_recursion_level +1);
			}
		}
		else
		    {
			if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2:%s:%d:ecoding boundaryless file (%s)...\n",FL,h->filename);
			result = MIME_decode_encoding( f, unpackdir, h );
		}

		return result;
	}



	if ((MIME_BS_top()!=NULL)&&(result == 0))
	{

		if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2:%s:%d:Decoding with boundaries (filename = %s)\n",FL,h->filename);

		// Explain this..... if the first headers of the message says RFC822, then we
		// have in effect a wrapped up message, a little crazy to have, but, happens
		// 	So, we dont want to try and read the headers in that case
		//

		result = MIME_decode_encoding(f, unpackdir, h);

		if (result == 0)
		{

			if (MIME_BS_top()!=NULL)
			{

				// As this is a multipart email, then, each section will have its
				// own headers, so, we just simply call the MIMEH_parse call again
				// and get the attachment details

				while (result == 0)
				{
					h->content_type = -1;
					h->filename[0] = '\0';
					h->name[0]     = '\0';
					h->content_transfer_encoding = -1;
					h->content_disposition = -1;

					if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2: Decoding headers...\n");
					result = MIMEH_parse_headers(f,h);
					if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2: result = %d\n",result);

					if (h->boundary_located)
					{
						if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2: Pushing boundary %s\n",h->boundary);
						MIME_BS_push(h->boundary);
						h->boundary_located = 0;
					}

					if (result == _MIMEH_FOUND_FROM)
					{
						return _MIMEH_FOUND_FROM;
					}

					if (result == 0)
					{

						// If we locate a new boundary specified, it means we have a
						// embedded message, also if we have a ctype of RFC822
						//
						if ( (h->boundary_located) \
						|| (h->content_type == _CTYPE_RFC822)\
					  	|| (h->content_type == _CTYPE_MULTIPART)\
					   )
						{
							if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2: Multipart mail headers found\n");

							/* If there is no filename, then we have a "standard"
							* embedded message, which can be just read off as a
							* continuous stream (simply with new boundaries */
							if (( h->content_transfer_encoding != _CTRANS_ENCODING_B64)&&(h->filename[0] == '\0' ))
							{
								if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2: NON-BASE64 DECODE\n");
								h->boundary_located = 0;
								result = MIME_unpack_stage2(f, unpackdir, h, current_recursion_level +1);

								p = MIME_BS_top();
								if (p) snprintf(h->boundary,_MIME_STRLEN_MAX,"%s",p);
							}
							else
							    {
								if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2: RFC822 Message to be decoded...\n");
								result = MIME_decode_encoding( f, unpackdir, h );
								if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_stage2: ... NOW running ripMIME over decoded RFC822 message...\n");

								// Because we're calling MIME_unpack_single again [ie, recursively calling it
								// we need to now adjust the input-filename so that it correctly is prefixed
								// with the directory we unpacked to.

								snprintf(scratch,sizeof(scratch),"%s/%s",unpackdir, h->filename);
								snprintf(h->filename,sizeof(h->filename),"%s",scratch);
								result = MIME_unpack_single( unpackdir, h->filename, current_recursion_level +1);
							}
						}
						else
						    {
							result = MIME_decode_encoding( f, unpackdir, h );
						}
					}
					else break;

				} // While (result)

				if (result == 0) MIME_BS_pop();

			} // if MIME_BS_top()

		} // if result == 0

	} // if (result)


	return result;
}






/*------------------------------------------------------------------------
Procedure:     MIME_decode_mailbox ID:1
Purpose:       Decodes mailbox formatted email files
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_unpack_mailbox( char *unpackdir, char *mpname, int current_recursion_level )
{
	FFGET_FILE f;
	FILE *fi;
	FILE *fo;
	char fname[1024];
	char line[1024];
	int mcount=0;
	int lastlinewasblank=1;
	int result;

	snprintf(fname,sizeof(fname),"%s/tmp.email000.mailpack",unpackdir);

	fi = fopen(mpname,"r");
	if (!fi)
	{
		if (syslogging > 0) syslog(_SL,"MIME_unpack_mailbox: Cannot open '%s' for reading (%s)",mpname,strerror(errno));
		if (stderrlogging > 0) fprintf(stderr,"MIME_unpack_mailbox: Cannot open '%s' for reading (%s)\n",mpname,strerror(errno));
		return -1;
	}

	fo = fopen(fname,"w");
	if (!fo)
	{
		if (syslogging > 0) syslog(_SL,"MIME_unpack_mailbox: Cannot open '%s' for writing  (%s)",fname,strerror(errno));
		if (stderrlogging > 0) fprintf(stderr,"MIME_unpack_mailbox: Cannot open '%s' for writing (%s)\n",fname,strerror(errno));
		return -1;
	}

	FFGET_setstream(&f, fi);

	while (FFGET_fgets(line,1024,&f))
	{
		// If we have the construct of "\n\rFrom ", then we
		//		can be -pretty- sure that a new email is about
		//		to start

		if ((lastlinewasblank==1)&&(strncasecmp(line,"From ",5)==0))
		{
			// Close the mailpack

			fclose(fo);

			// Now, decode the mailpack

			MIME_unpack_single(unpackdir, fname, current_recursion_level);

			// Remove the now unpacked mailpack

			result = remove(fname);
			if (result == -1)
			{
				if (syslogging > 0) syslog(_SL,"MIME_unpack_mailbox: Error removing temporary mailpack '%s' (%s)",fname,strerror(errno));
			}

			// Create a new mailpack filename, and keep on going...

			snprintf(fname,sizeof(fname),"%s/tmp.email%03d.mailpack",unpackdir,++mcount);
			fo = fopen(fname,"w");
		}
		else
		{
			fprintf(fo,"%s",line);
		}

		// If the line is blank, then note this down because
		// 	if our NEXT line is a From, then we know that
		//		we have reached the end of the email
		//
		if ((line[0] == '\n') || (line[0] == '\r'))
		{
			lastlinewasblank=1;
		}
		else lastlinewasblank=0;

	} // While fgets()

	fclose(fi);

	// Now, even though we have run out of lines from our main input file
	// 	it DOESNT mean we dont have some more decoding to do, in fact
	//		quite the opposite, we still have one more file to decode

	// Close the mailpack

	fclose(fo);

	// Now, decode the mailpack

	MIME_unpack_single(unpackdir, fname, current_recursion_level);

	// Remove the now unpacked mailpack

	result = remove(fname);
	if (result == -1)
	{
		if (syslogging > 0) syslog(_SL,"MIME_unpack_mailbox: Error removing temporary mailpack '%s' (%s)",fname,strerror(errno));
	}

	return 0;
}



/*------------------------------------------------------------------------
Procedure:     MIME_unpack_single ID:1
Purpose:       Decodes a single mailpack file (as apposed to mailbox format) into its
possible attachments and text bodies
Input:         char *unpackdir: Directory to unpack the attachments to
char *mpname: Name of the mailpack we have to decode
int current_recusion_level: Level of recursion we're currently at.
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_unpack_single( char *unpackdir, char *mpname, int current_recursion_level )
{
	struct _header_info h;
	int result = 0;
	int status = 0;		/* Global status */
	int headers_save_set_here = 0;

	FFGET_FILE f;
	FILE *fi;			/* Pointer for the MIME file we're going to be going through */
	FILE *hf = NULL;


	// Because this MIME module gets used in both CLI and daemon modes
	// 	we should check to see that we can report to stderr
	//

//	_MIME_debug = (_MIME_debug & stderrlogging);

	if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_single: dir=%s packname=%s level=%d (max = %d)\n",unpackdir, mpname, current_recursion_level, _RECURSION_LEVEL_MAX);

	if (current_recursion_level > _RECURSION_LEVEL_MAX)
	{
		if (syslogging > 0) syslog(_SL,"MIME_unpack_single: Current Recursion level of %d is greater than permitted %d",current_recursion_level, _RECURSION_LEVEL_MAX);
		if (stderrlogging > 0) fprintf(stderr,"MIME_unpack_single: Current Recursion level of %d is greater than permitted %d\n",current_recursion_level, _RECURSION_LEVEL_MAX);
		return -1;
	}
	else h.current_recursion_level = current_recursion_level;

	_current_line = 0;

	if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_single: Recursion level checked...\n");

	/* if we're reading in from STDIN */
	if( mpname[0] == '-' && mpname[1] == '\0' )
	{
		if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_single: STDIN opened...\n");
		fi = stdin;
	}
	else
	{
		fi = fopen(mpname,"r");
		if (!fi)
		{
			if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_single: WARNING failed to open new mailpack\n");
			if (syslogging > 0) syslog(_SL,"MIME_unpack_single: Error opening '%s' for reading (%s)",mpname,strerror(errno));
			return -1;
		}
		if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_single: Input file (%s) opened...\n",mpname);

	}

	if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_single: DumpHeaders = %d\n", _dump_headers);

	if ((!hf)&&(_dump_headers)&&(MIMEH_get_headers_save()==0))
	{
		// Prepend the unpackdir path to the headers file name

		snprintf(scratch,sizeof(scratch),"%s/%s",unpackdir, headersname);
		hf = fopen(scratch,"w");
		if (!hf)
		{
			_dump_headers = 0;
			if (syslogging > 0) syslog(_SL,"MIME_unpack_single: Cannot open '%s' for writing  (%s)",headersname,strerror(errno));
			if (stderrlogging > 0) fprintf(stderr,"MIME_unpack_single: Cannot open '%s' for writing (%s)\n",headersname,strerror(errno));
		}
		else
		    {
			headers_save_set_here = 1;
			MIMEH_set_headers_save(hf);
		}
	}




	if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_single: Checking input streams...\n");

	/* check to see if we had problems opening the file */
	if (!fi)
	{
		if (syslogging > 0) syslog(_SL,"MIME_unpack_single: Could not open mailpack file '%s' (%s)",mpname, strerror(errno));
		if (stderrlogging > 0) fprintf(stderr,"MIME_unpack_single: Could not open mailpack file '%s' (%s)\n\n",mpname, strerror(errno));
		return -1;
	}

	if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_single: Setting up streams to decode...\n");
	FFGET_setstream(&f, fi);

	h.content_type = -1;
	h.boundary[0] = '\0';
	h.boundary_located = 0;
	h.filename[0] = '\0';
	h.name[0]     = '\0';
	h.content_transfer_encoding = -1;
	h.content_disposition = -1;

	if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_single: preparing to decode (calling stage2...\n");
	result = MIME_unpack_stage2(&f, unpackdir, &h, 0);
	if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_single: done decoding (%s/%s)\n",unpackdir,mpname);

	fclose(fi);

	if ( headers_save_set_here > 0 )
	{
		if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_single: Closing header file.\n"); fflush(stdout);
		MIMEH_set_headers_nosave();
		fclose(hf);
	}

	if (MIME_DNORMAL) fprintf(stdout,"MIME_unpack_single: Done.\n");

	return status;
}






/*------------------------------------------------------------------------
Procedure:     MIME_unpack ID:1
Purpose:       Front end to unpack_mailbox and unpack_single.  Decides
which one to execute based on the mailbox setting
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIME_unpack( char *unpackdir, char *mpname, int current_recursion_level )
{
	int result = 0;

	if (_mailbox_format > 0)
		result = MIME_unpack_mailbox( unpackdir, mpname, current_recursion_level );
	else
	    result = MIME_unpack_single( unpackdir, mpname, current_recursion_level );

	MIME_BS_clear();

	return result;

}






/*--------------------------------------------------------------------
* MIME_close
*
* Closes the files used in MIME_unpack, such as headers etc */
int MIME_close( void )
{
	if (headers)
	{
		fclose(headers);
	}

	return 0;
}




/*----------END OF MIME.c------------*/

