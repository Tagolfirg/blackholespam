#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


#include "ffget.h"
#include "XAM_strtok.h"
#include "strlower.h"
#include "zstr.h"
#include "MIME_headers.h"


// Debug precodes
#define MIMEH_DPEDANTIC ((_MIMEH_debug >= _MIMEH_DEBUG_PEDANTIC))
#define MIMEH_DNORMAL   ((_MIMEH_debug >= _MIMEH_DEBUG_NORMAL  ))

int MIMEH_doubleCR = 0;
char MIMEH_doubleCRname[_MIMEH_STRLEN_MAX +1];

char *MIMEH_headerline = NULL;
int MIMEH_save_headers = 0;
int MIMEH_test_mailbox = 0;
int _MIMEH_debug = 0;
int _MIMEH_webform = 0;
int _MIMEH_doubleCR_count = 0;
int _MIMEH_verbose = 0;
char _MIMEH_outputdir[_MIMEH_STRLEN_MAX +1]="";
//	16/11/2001	suggestion to use the static operation by Mark Leisher <mleisher@crl.nmsu.edu>
static char hexconv[256];


FILE *MIMEH_fh;



int MIMEH_set_debug( int level )
{
	_MIMEH_debug = level;
	return _MIMEH_debug;
}

int MIMEH_set_outputdir( char *dir )
{
	if (dir) snprintf(_MIMEH_outputdir,_MIMEH_STRLEN_MAX,"%s",dir);
	return 0;
}

int MIMEH_set_webform( int level )
{
	_MIMEH_webform = level;
	return _MIMEH_webform;
}


int MIMEH_set_mailbox( int level )
{
	MIMEH_test_mailbox = level;
	return level;
}

int MIMEH_set_verbosity( int level )
{
	_MIMEH_verbose = level;
	return level;
}

/*---------------------------------------------------
* MIME_init_hexconv()
*
 * Initialises the hex->dec conversion
*
 */
int MIMEH_init_hexconv( void )
{

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

	return 0;
}


/*------------------------------------------------------------------------
Procedure:     MIMEH_decode_qp ID:1
Purpose:       Decodes a given line from QuotePrintable format to plain text
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIMEH_decode_qp( char *line )
{

	char c;								/* The Character to output */
	int op, ip; 						/* OutputPointer and InputPointer */
	int slen = strlen(line); /* Length of our line */

	/* Initialise our "pointers" to the start of the encoded string */
	ip=op=0;

	/* for every character in the string... */
	for (ip = 0; ip < slen; ip++){

		c = line[ip];

		/* if we have the quote-printable esc char, then lets get cracking */
		if (c == '=')
		{
			/* if we have another two chars... */
			if (ip <= (slen-2)){

				/* convert our encoded character from HEX -> decimal */
				c = (char)hexconv[(int)line[ip+1]]*16 +hexconv[(int)line[ip+2]];

				/* shuffle the pointer up two spaces */
				ip+=2;
			} /* if there were two extra chars after the ='s */

			/* if we didn't have enough characters, then  we'll make the char the
			* string terminator (such as what happens when we get a =\n
			*/
			else {
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

	return 0;

}







/*------------------------------------------------------------------------
Procedure:     MIMEH_set_headers_save ID:1
Purpose:       Sets MIMEH's headers save file (where MIMEH will save the
headers it reads in from the mailpack)
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIMEH_set_headers_save( FILE *f )
{
	MIMEH_fh = f;
	MIMEH_save_headers = 1;
	return 0;
}

int MIMEH_set_headers_nosave( void )
{
	MIMEH_fh = NULL;
	MIMEH_save_headers = 0;
	return 0;
}

int MIMEH_get_headers_save( void )
{
	return MIMEH_save_headers;
}


int MIMEH_save_doubleCR( FFGET_FILE *f )
{
	int c;
	FILE *fo;
	struct stat st;


	// Determine a file name we can use.

	do {
		_MIMEH_doubleCR_count++;
		snprintf(MIMEH_doubleCRname,_MIMEH_STRLEN_MAX,"%s/doubleCR.%d",_MIMEH_outputdir,_MIMEH_doubleCR_count);
	}
	while (stat(MIMEH_doubleCRname, &st) == 0);


	fo = fopen(MIMEH_doubleCRname,"w");
	if (!fo)
	{
		syslog(1,"MIMEH_save_doubleCR: Error, unable to open '%s' to write (%s)",MIMEH_doubleCRname,strerror(errno));
		return -1;
	}

	if (_MIMEH_verbose)	fprintf(stdout,"Saving DoubleCR header: %s\n",MIMEH_doubleCRname);

	while (1)
	{
		c = FFGET_fgetc(f);
		fprintf(fo,"%c",c);
		if ((c == EOF)||(c == '\n'))
		{
			break;
		}
	}

	fclose(fo);

	return 0;
}


/*------------------------------------------------------------------------
Procedure:     MIMEH_read_headers ID:1
Purpose:       Reads from the stream F until it detects a From line, or a blank line
(end of headers)
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIMEH_read_headers( FFGET_FILE *f )
{
	char line[_MIMEH_STRLEN_MAX+1];
	int totalsize=0;
	int linesize=0;
	int result = 0;
	int firstline = 1;
	int hl;
	char *tmp;
	char *fget_result = NULL;
	char *headerline_end;

	MIMEH_headerline = NULL;

	if (MIMEH_DNORMAL) fprintf(stdout,"DEBUG: MIME_headers: Starting read\n");


	while ((fget_result=FFGET_fgets(line,_MIMEH_STRLEN_MAX, f)))
	{

		if (MIMEH_DNORMAL) fprintf(stdout,"DEBUG: MIME_headers: [blank = %d] Read: \n%s",f->trueblank,line);

		linesize = strlen(line);
		totalsize += linesize;
		tmp = realloc(MIMEH_headerline, totalsize+1);

		if (!tmp)
		{
			syslog(1,"MIMEH_read_headers(): cannot allocate %d bytes ",totalsize);
			free(MIMEH_headerline);
			MIMEH_headerline = NULL;
			return -1;
		}

		if (!MIMEH_headerline)
		{
			MIMEH_headerline = tmp;
			zstrncpy(MIMEH_headerline, line, (linesize +1));
			headerline_end = MIMEH_headerline +totalsize;
		}
		else
		    {
			hl = totalsize -linesize;
			MIMEH_headerline = tmp;
			memcpy((MIMEH_headerline +hl), line, (linesize+1));
			//			strcat(MIMEH_headerline,line);
						}


		if (f->trueblank)
		{

			if (MIMEH_DNORMAL) fprintf(stdout,"DEBUG: MIME_headers: True BLANK LINE located, terminating header read\n");

			if ((MIMEH_save_headers)&&(MIMEH_headerline))
			{
				fprintf(MIMEH_fh,"%s",MIMEH_headerline);
			}
			if (MIMEH_DNORMAL) 			fprintf(stdout,"%s:%d------------------headers:\n%s\n(TRUE-END Found)\n",__FILE__,__LINE__,MIMEH_headerline);
			result = 1;
			break;
		}


		// If there was a doubleCR at the end of the line,
		//	then we need to save the next set of data until there
		//	is a \n

		if (FFGET_doubleCR)
		{
			MIMEH_save_doubleCR(f);
			FFGET_doubleCR = 0;
			MIMEH_doubleCR = 1;
			FFGET_SDL_MODE = 0;
		}

		firstline = 0;
	}


	// If FFGET ran out of data whilst processing the headers, then acknowledge this
	// by returning a -1.
	//
	// NOTE - This does not mean we do not have any data!
	//  it just means that our input ran out.

	if (!fget_result)
	{
		result = -1;
	}

	//	fprintf(stderr,"DEBUG:Exiting MIME_read_headers()\n");
	return result;
}



/*------------------------------------------------------------------------
Procedure:     MIMEH_display_info ID:1
Purpose:       DEBUGGING - Displays the values of the hinfo structure to
stderr
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIMEH_display_info( struct _header_info *hinfo )
{
	if (hinfo)
	{
		fprintf(stdout,"\
Content Type = %d\n\
Boundary = %s\n\
Filename = %s\n\
    name = %s\n\
Encoding = %d\n\
Disposit = %d\n\
"\
,hinfo->content_type\
,hinfo->boundary\
,hinfo->filename\
,hinfo->name\
,hinfo->content_transfer_encoding\
,hinfo->content_disposition);
		fflush(stdout);
	}
	return 0; // I was a dilly to use return 1 as std... totally against normal C programming methods!

}




/*------------------------------------------------------------------------
Procedure:     MIMEH_parse_filename ID:1
Purpose:       Reads in a given filename, and cleans it up, removes any risky
components
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int MIMEH_parse_filename( char *dest, char *raw )
{
	char c = '\0';
	char *p, *q, *n;
	int qp_encode = 0;
	int quoted = 0;
	char tmp[_MIMEH_STRLEN_MAX+1];

	n = strpbrk(raw,"\n\r;");
	if (n)
	{
		c = *n;
		*n = '\0';
	}

	zstrncpy(tmp,raw,_MIMEH_STRLEN_MAX);
	p = tmp;

	if (XAM_strncasecmp(p,"\"3d",3)==0)
	{
		qp_encode = 1;
		quoted=1;
		p+=3;
	}
	else
		if (XAM_strncasecmp(p,"3d\"",3)==0)
		{
			qp_encode = 1;
			quoted = 1;
			p+=3;
		}
		else
			if (XAM_strncasecmp(p,"3d",2)==0)
			{
				qp_encode = 1;
				quoted=0;
				p+=2;
			}
			else
				if ((*p) == '\"')
				{
					qp_encode = 0;
					quoted = 1;
					p++;
				}


	if ((qp_encode)&&(strstr(p,"=OA="))) qp_encode = 1;
	else qp_encode = 0;

	snprintf(dest,_MIMEH_FILENAMELEN_MAX,"%s",p);

	if (qp_encode) MIMEH_decode_qp(dest);

	if (quoted)
	{
		q = strrchr(dest,'\"');
		if (q) *q = '\0';
	}

	if (n) *n = c;

	return 0;
}




/*------------------------------------------------------------------------
Procedure:     MIMEH_parse_headers ID:1
Purpose:       Reads an open filestream in and parses the headers for it.
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int   MIMEH_parse_headers( FFGET_FILE *f, struct _header_info *hinfo )
{
	char *safeh, *h, *hl, *safehl;
	char *p,*q, c, *pre_p;
	char *lba;
	char *line_end;
	char *next_angle;
	int result;
	int headerlength;

	if (MIMEH_DNORMAL) fprintf(stdout,"MIMEH_parse_headers: Start [F=%p, hinfo=%p]\n", f, hinfo);
	MIMEH_init_hexconv();

	FFGET_set_watch_SDL(1);
	result = MIMEH_read_headers(f);
	FFGET_set_watch_SDL(0);

	hinfo->filename[0] = '\0';
	hinfo->name[0] = '\0';

	safeh = h = MIMEH_headerline;

	// If we ran out of input whilst looking at headers, then, we basically
	// flag this, free up the headers, and return.

	if (result == -1)
	{
		if (MIMEH_headerline) free(MIMEH_headerline);
		return result;
	}

	if (!MIMEH_headerline)
	{
		if (MIMEH_DNORMAL) 		fprintf(stderr,"DEBUG:%s:%d: null MIMEH_headerline\n",__FILE__,__LINE__);
		return 1;
	}


	// Duplicate string
	headerlength = strlen(h);
	safehl = hl = malloc(sizeof(char) *(headerlength+1));
	zstrncpy(hl,h, headerlength+1);
	strlower(hl);

	if (MIMEH_DNORMAL) 	fprintf(stdout,"DEBUG:%s:%d: Header length = %d\n",__FILE__,__LINE__,headerlength);





	// CONTENT TYPE -------------------------------
	// CONTENT TYPE -------------------------------
	// CONTENT TYPE -------------------------------


	hinfo->content_type = _CTYPE_UNKNOWN;

	p = strstr(hl,"content-type");
	if (p)
	{
		p = p +strlen("content-type");
		q = strpbrk(p,"\n\r;");
		if (q)
		{
			c = *q;
			*q = '\0';

			if (strstr(p,"multipart/")) hinfo->content_type = _CTYPE_MULTIPART;
			else
			    if (strstr(p,"text/")) hinfo->content_type = _CTYPE_TEXT;
			else
			    if (strstr(p,"message/rfc822")) hinfo->content_type = _CTYPE_RFC822;
			else
			    if (strstr(p,"/octet-stream")) hinfo->content_type = _CTYPE_OCTECT;
			else
			    if (strstr(p,"/ms-tnef")) hinfo->content_type = _CTYPE_TNEF;
			else hinfo->content_type = _CTYPE_UNKNOWN;

			*q = c;
		}
		else
		{
			syslog(1,"MIMEH_parse_headers(): Cannot locate end of Content-Type specifier!");
		}
	}








	// CONTENT LOCATION -------------------------------
	// CONTENT LOCATION -------------------------------
	// CONTENT LOCATION -------------------------------

	p = strstr(hl,"content-location:");
	if (p)
	{
		if (MIMEH_DNORMAL) 		fprintf(stdout,"%s:%d: Content Location line found - '%s'\n",__FILE__,__LINE__,p);
		q = strrchr(p,'/');
		if (!q) q = strrchr(p,':');
		if (q)
		{
			p = h +(q -hl);
			MIMEH_parse_filename(hinfo->filename, p);
			snprintf(hinfo->name,sizeof(hinfo->name),"%s",hinfo->filename);

		}
		else hinfo->filename[0] = '\0';
	}







	// ATTACHMENT FILENAME ----------------------------
	// ATTACHMENT FILENAME ----------------------------
	// ATTACHMENT FILENAME ----------------------------

	p = strstr(hl,"filename=");
	if (p)
	{
		if (MIMEH_DNORMAL) 		fprintf(stdout,"MIME_headers: %d: %s",__LINE__,hl);
		p = p +strlen("filename=");
		p = h +(p -hl);
		MIMEH_parse_filename(hinfo->filename, p);
		snprintf(hinfo->name,sizeof(hinfo->name),"%s",hinfo->filename);
	}
	else hinfo->filename[0] = '\0';




	// ATTACHMENT -NAME ----------------------------
	// ATTACHMENT -NAME ----------------------------
	// ATTACHMENT -NAME ----------------------------

	if (hinfo->filename[0] == '\0')
	{
		p = strstr(hl,"name=");
		if ( (p) && (isspace(*(p-1))) )
		{
			// Because HTML in MIME is so common these days, it's not
			// unusual to get a <META .... name="..."> tag in the headers
			// hence, it's a good idea to text for the trailing > (which
			// is not a legal filechar anyhow!) and REJECT if it contains
			// it

			next_angle = line_end = NULL;
			next_angle=strchr(p,'>');
			if (next_angle) line_end=strpbrk(p,"\n\r\";");
			if ( (!next_angle) || (line_end && (line_end < next_angle)) )
			{
				p = p +strlen("name=");
				p = h +(p -hl);
				MIMEH_parse_filename(hinfo->name, p);
			}
		}
	}


	// If we got a filename in one, but not the other hinfo-> seach, then
	// Duplicate

	if ((hinfo->filename[0] == '\0')&&(hinfo->name[0] != '\0'))
	{
		snprintf(hinfo->filename,_MIMEH_FILENAMELEN_MAX,"%s",hinfo->name);
	}




	// CONTENT TRANSFER ENCODING ---------------------
	// CONTENT TRANSFER ENCODING ---------------------
	// CONTENT TRANSFER ENCODING ---------------------


	p = strstr(hl,"content-transfer-encoding");
	if (p)
	{
		p = p +strlen("content-transfer-encoding");
		q = strpbrk(p,"\n\r;");
		if (q)
		{
			c = *q;
			*q = '\0';

			if (strstr(p,"base64"))
			{
				hinfo->content_transfer_encoding = _CTRANS_ENCODING_B64;
			}
			else
			    if (strstr(p,"7bit"))
			{
				hinfo->content_transfer_encoding = _CTRANS_ENCODING_7BIT;
			}
			else
			    if (strstr(p,"8bit"))
			{
				hinfo->content_transfer_encoding = _CTRANS_ENCODING_8BIT;
			}
			else
			    if (strstr(p,"quoted-printable"))
			{
				hinfo->content_transfer_encoding = _CTRANS_ENCODING_QP;
			}
			else
			    if (strstr(p,"uuencode"))
			{
				hinfo->content_transfer_encoding = _CTRANS_ENCODING_UUENCODE;
			}
			else hinfo->content_transfer_encoding = _CTRANS_ENCODING_RAW;

			*q = c;
		}
		else
		{
			syslog(1,"MIMEH_parse_headers(): Cannot locate end of Content-Transfer-Encoding specifier!");
		}
	}
	else hinfo->content_transfer_encoding = _CTRANS_ENCODING_RAW;







	// CONTENT DISPOSITION ------------------------------
	// CONTENT DISPOSITION ------------------------------
	// CONTENT DISPOSITION ------------------------------

	p = strstr(hl,"content-disposition");
	if (p)
	{
		p = p +strlen("content-disposition");
		q = strpbrk(p,"\n\r;");
		if (q)
		{
			c = *q;
			*q = '\0';

			if (strstr(p,"inline")) hinfo->content_disposition = _CDISPOSITION_INLINE;
			else
			    if (strstr(p,"form-data"))
			{
				hinfo->content_disposition = _CDISPOSITION_FORMDATA;
				hinfo->content_type = _CDISPOSITION_FORMDATA;
			}
			else
			    if (strstr(p,"attachment")) hinfo->content_disposition = _CDISPOSITION_ATTACHMENT;
			else hinfo->content_disposition = _CDISPOSITION_UNKNOWN;

			*q = c;
		}
		else
		{
			syslog(1,"MIMEH_parse_headers(): Cannot locate end of Content-Disposition specifier!");
		}
	}





	// Seeking out boundaries is not quite as simple as it seems.
	// we can "initially" think that we can just do a "strstr", but
	// what if there is a filename="someboundary=OAxxx.gif" then
	// we're in trouble!
	//

	lba = hl;
	p = strstr(lba, "boundary=");
	while ( (lba != NULL) && (hinfo->boundary_located==0)  && ( p != NULL) )
	{
		if (MIMEH_DNORMAL) fprintf(stdout,"DEBUG:MIME_headers:%s:%d:Looking for headers...(%s)\n",__FILE__,__LINE__,(p-2));

		if (p == NULL) break;

		// Setup a pointer to the char just before this boundary= location

		if (p > hl)
		{
			pre_p = p -1;
		}
		else pre_p = NULL;


		// If the previous char from 'p' is not a ; or "space", then it's not possible for this
		// to be a BOUNDARY

		if ( (pre_p) && (!isspace(*pre_p)) && (*pre_p != ';') )
		{
			if (MIMEH_DNORMAL) fprintf(stdout,"DEBUG:%s:%d:Previous char '%c' is NOT blank, move along now...\n",__FILE__,__LINE__, *pre_p);
			p = strstr(p +strlen("boundary="),"boundary=");
			continue;
		}

		//		fprintf(stdout,"Testing boundary at: %s",p);
		p = p +strlen("boundary=");
		p = h +(p -hl);

		// If we have a quoted boundary, shift one char to the right
		if ((*p) == '\"') p++;

		// Try to find the end of the boundary by looking for ", \n, \r \t or ;
		q = strpbrk(p,"\"\n\r\t;");

		// If we did find something for the end of the boundary
		if (q)
		{
			// If the first char of the boundary isn't a normal alphanumeric char
			if (!(isprint(*p)))
			{

				// Move our start point (for detecting boundaries in the headers)
				// alone one more char...
				lba++;

				// Try find a new boundary...
				p = strstr(lba,"boundary=");
				continue;
			}
			else
			    {

				// if the character was valid, then we have detected a boundary
				// specifier!.  Copy this to the hinfo structure, and set the
				// "located" flag

				// get the character which we stopped on
				c = *q;

				// turn the location into a string terminator
				*q = '\0';


				snprintf(hinfo->boundary,_MIMEH_STRLEN_MAX,"%s",p);
				hinfo->boundary_located = 1;
				*q = c;
			}

			// Set our string terminator location back to its original character
			// (if we dont, then any further string operations wont see beyond
			// it)

		}
		else
		{
			syslog(1,"MIMEH_parse_headers(): Cannot locate end of boundary specifier!");
		}
	} // while


	if (safehl) free(safehl);
	else fprintf(stderr,"%s:%d:WARNING - Unable to free HEADERS allocated memory\n",__FILE__,__LINE__);//	if (hlorg) free(hlorg);


	if (safeh)
	{
		free(safeh);
		MIMEH_headerline = NULL;
	}
	else fprintf(stdout,"%s:%d:WARNING - Unable to free HEADERS allocated memory\n",__FILE__,__LINE__);

	if (MIMEH_DNORMAL) fprintf(stdout,"MIMEH_parse_headers: END [F=%p, hinfo=%p]\n", f, hinfo);

	return 0;
}

