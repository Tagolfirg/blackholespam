/***************************************************************************
 * tnef2txt
*   A program to decode application/ms-tnef MIME attachments into text
*   for those fortunate enough not to be running either a Microsoft
*   operating system or mailer.
*
 * 18/10/2001
* Brutally cropped by Paul L Daniels (pldaniels@pldaniels.com) in order
* to accommodate the needs of ripMIME/Xamime/Inflex without carrying too
* much excess baggage.
*
 * Brandon Long (blong@uiuc.edu), April 1997
* 1.0 Version
*   Supports most types, but doesn't decode properties.  Maybe some other
*   time.
*
 * 1.1 Version (7/1/97)
*   Supports saving of attAttachData to a file given by attAttachTitle
*   start of property decoding support
*
 * 1.2 Version (7/19/97)
*   Some architectures don't like reading 16/32 bit data on unaligned
*   boundaries.  Fixed, losing efficiency, but this doesn't really
*   need efficiency anyways.  (Still...)
*   Also, the #pragma pack from the MSVC include file wasn't liked
*   by most Unix compilers, replaced with a GCCism.  This should work
*   with GCC, but other compilers I don't know.
*
 * 1.3 Version (7/22/97)
*   Ok, take out the DTR over the stream, now uses read_16.
*
 * NOTE: THIS SOFTWARE IS FOR YOUR PERSONAL GRATIFICATION ONLY.  I DON'T
* IMPLY IN ANY LEGAL SENSE THAT THIS SOFTWARE DOES ANYTHING OR THAT IT WILL
* BE USEFULL IN ANY WAY.  But, you can send me fixes to it, I don't mind.
***************************************************************************/

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include "config.h"
#include "tnef.h"
#include "mapidefs.h"
#include "mapitags.h"
#include "tnef_api.h"
#include "../logger.h"

#define VERSION "pldtnef/0.0.1"

int _TNEF_syslogging = 0;
int _TNEF_stderrlogging = 1;
int _TNEF_verbose = 0;
int _TNEF_debug = 0;

int Verbose = FALSE;
int SaveData = FALSE;

char _TNEF_path[1024]="";


uint8 *tnef_home;
uint8 *tnef_limit;

int save_attach_data(char *, uint8 *, uint32);

/*------------------------------------------------------------------------
Procedure:     TNEF_set_path ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int TNEF_set_path( char *path )
{
	snprintf(_TNEF_path,1023,"%s",path);

	return 0;
}


/*------------------------------------------------------------------------
Procedure:     TNEF_set_verbosity ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int TNEF_set_verbosity( int level )
{
	_TNEF_verbose = level;
	return _TNEF_verbose;
}




/*------------------------------------------------------------------------
Procedure:     TNEF_set_debug ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int TNEF_set_debug( int level )
{
	_TNEF_debug = level;
	TNEF_set_verbosity( level );
	return _TNEF_debug;
}



/*------------------------------------------------------------------------
Procedure:     TNEF_set_syslogging ID:1
Purpose:       Turns on/off the syslog feature for TNEF error messages
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int TNEF_set_syslogging( int level )
{
	_TNEF_syslogging = level;
	return _TNEF_syslogging;
}




/*------------------------------------------------------------------------
Procedure:     TNEF_set_stderrlogging ID:1
Purpose:       Turns on/off the stderr feature for TNEF error messages
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int TNEF_set_stderrlogging( int level )
{
	_TNEF_stderrlogging = level;
	return _TNEF_stderrlogging;
}


/* Some systems don't like to read unaligned data */
/*------------------------------------------------------------------------
Procedure:     read_32 ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
uint32 read_32(uint8 *tsp)
{
	uint8 a,b,c,d;
	uint32 ret;

	//	if (_TNEF_debug) fprintf(stderr,"Read_32: Offset read %d\n", tsp -tnef_home);

	if (tsp > tnef_limit)
	{
		if ((_TNEF_verbose)||(_TNEF_stderrlogging)||(_TNEF_debug)) fprintf(stderr,"TNEF read_32() Attempting to read past end\n");
		if (_TNEF_syslogging > 0) LOGGER_log("TNEF_read_32: Error - trying to read beyond end of memory block");
		return -1;
	}

	a = *tsp;
	b = *(tsp+1);
	c = *(tsp+2);
	d = *(tsp+3);

	ret =  long_little_endian(a<<24 | b<<16 | c<<8 | d);

	return ret;
}

/*------------------------------------------------------------------------
Procedure:     read_16 ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
uint16 read_16(uint8 *tsp)
{
	uint8 a,b;
	uint16 ret;

	if (tsp > tnef_limit)
	{
		if ((_TNEF_verbose)||(_TNEF_stderrlogging)||(_TNEF_debug)) fprintf(stderr,"TNEF read_16() Attempting to read past end\n");
		if (_TNEF_syslogging > 0) LOGGER_log("TNEF_read_16: Error - trying to read beyond end of memory block");
		return -1;
	}

	//	if (_TNEF_debug) fprintf(stderr,"Read_16: Offset read %d\n", tsp -tnef_home);

	a = *tsp;
	b = *(tsp + 1);

	ret = little_endian(a<<8 | b);

	return ret;
}



/*------------------------------------------------------------------------
Procedure:     make_string ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
char *make_string(uint8 *tsp, int size)
{
	static char s[256] = "";
	int len = (size>sizeof(s)-1) ? sizeof(s)-1 : size;

	strncpy(s,tsp, len);
	s[len] = '\0';
	return s;
}


/*------------------------------------------------------------------------
Procedure:     handle_props ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int handle_props(uint8 *tsp)
{
	int bytes = 0;
	uint32 num_props = 0;
	uint32 x = 0;


	num_props = read_32(tsp);
	bytes += sizeof(num_props);

	while (x < num_props)
	{
		uint32 prop_tag;
		uint32 num;
		char filename[256];
		static int file_num = 0;

		prop_tag = read_32(tsp+bytes);
		bytes += sizeof(prop_tag);

		switch (prop_tag & PROP_TYPE_MASK)
		{
		case PT_BINARY:
			num = read_32(tsp+bytes);
			bytes += sizeof(num);
			num = read_32(tsp+bytes);
			bytes += sizeof(num);
			if (prop_tag == PR_RTF_COMPRESSED)
			{
				sprintf (filename, "XAM_%d.rtf", file_num);
				file_num++;
				save_attach_data(filename, tsp+bytes, num);
			}
			/* num + PAD */
			bytes += num + ((num % 4) ? (4 - num%4) : 0);
			break;
		case PT_STRING8:
			num = read_32(tsp+bytes);
			bytes += sizeof(num);
			num = read_32(tsp+bytes);
			bytes += sizeof(num);
			make_string(tsp+bytes,num);
			bytes += num + ((num % 4) ? (4 - num%4) : 0);
			break;
		case PT_UNICODE:
		case PT_OBJECT:
			break;
		case PT_I2:
			bytes += 2;
			break;
		case PT_LONG:
			bytes += 4;
			break;
		case PT_R4:
			bytes += 4;
			break;
		case PT_DOUBLE:
			bytes += 8;
			break;
		case PT_CURRENCY:
		case PT_APPTIME:
		case PT_ERROR:
			bytes += 4;
			break;
		case PT_BOOLEAN:
			bytes += 4;
			break;
		case PT_I8:
			bytes += 8;
		case PT_SYSTIME:
			bytes += 8;
			break;
		}
		x++;
	}

	return 0;
}




/*------------------------------------------------------------------------
Procedure:     save_attach_data ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int save_attach_data(char *title, uint8 *tsp, uint32 size)
{
	FILE *out;
	char filename[1024];

	/*
	if ((*tsp +size) > _TNEF_size)
	{
	if (_TNEF_syslogging > 0) LOGGER_log("TNEF_save_attach_data: Attempting to save more data than exists, suspect endian-issue with compile (%d vs %d)",(*tsp+size),_TNEF_size);
	return -1;
	}
	*/
	snprintf(filename,1023,"%s/%s",_TNEF_path,title);

	out = fopen(filename, "w");
	if (!out)
	{
		if (_TNEF_stderrlogging > 0) fprintf(stderr, "Error openning file %s for writing\n", filename);
		if (_TNEF_syslogging > 0) LOGGER_log("TNEF_save_attach_data: Error opening file %s for writing (%s)",filename,strerror(errno));
		return -1;
	}

	fwrite(tsp, sizeof(uint8), size, out);
	fclose(out);
	return 0;
}




/*------------------------------------------------------------------------
Procedure:     default_handler ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int default_handler(uint32 attribute, uint8 *tsp, uint32 size)
{
	uint16 type = ATT_TYPE(attribute);

	switch (type) {
	case atpTriples:
		break;
	case atpString:
	case atpText:
		break;
	case atpDate:
		break;
	case atpShort:
		break;
	case atpLong:
		break;
	case atpByte:
		break;
	case atpWord:
		break;
	case atpDword:
		break;
	default:
		break;
	}
	return 0;

}




/*------------------------------------------------------------------------
Procedure:     read_attribute ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int read_attribute(uint8 *tsp)
{

	int bytes = 0, header = 0;
	uint32 attribute;
	uint8 component = 0;
	uint32 size = 0;
	uint16 checksum = 0;
	static char attach_title[256] = {
		0				};
	static uint32 attach_size = 0;
	static uint32 attach_loc  = 0;

	// What component are we look at?
 //
 component = *tsp;

	bytes += sizeof(uint8);

	// Read the attributes of this component

	if (_TNEF_debug) fprintf(stderr,"read_attribute: Reading Attribute...\n");
	attribute = read_32(tsp+bytes);
	if (attribute == -1) return -1;
	bytes += sizeof(attribute);

	// Read the size of the information we have to read

	if (_TNEF_debug) fprintf(stderr,"read_attribute: Reading Size...\n");
	size = read_32(tsp+bytes);
	if (size == -1) return -1;
	bytes += sizeof(size);

	// The header size equals the sum of all the things we've read
 	//  so far.

	header = bytes;

	// The is a bit of a tricky one [if you're being slow
	//  it moves the number of bytes ahead by the amount of data of
 	//  the attribute we're about to read, so that for next
	//  "read_attribute()"
	//  call starts in the right place.

	bytes += size;

	// Read in the checksum for this component
	//
	// AMMENDMENT - 19/07/02 - 17H01
	// Small code change to deal with strange sitations that occur with non
	//		english characters. - Submitted by wtcheuk@netvigator.com @ 19/07/02

	if ( bytes < 0 ) return -1;

	// --END of ammendment.

	if (_TNEF_debug) fprintf(stderr,"read_attribute: Reading Checksum...(offset %d, bytes=%d)\n", tsp -tnef_home, bytes);
	checksum = read_16(tsp+bytes);
	bytes += sizeof(checksum);

	if (_TNEF_debug) fprintf(stderr,"Decoding attribute %d\n",attribute);

	switch (attribute) {
	case attNull:
		default_handler(attribute, tsp+header, size);
		break;
	case attFrom:
		default_handler(attribute, tsp+header, size);
		break;
	case attSubject:
		break;
	case attDateSent:
		break;
	case attDateRecd:
		break;
	case attMessageStatus:
		break;
	case attMessageClass:
		break;
	case attMessageID:
		break;
	case attParentID:
		break;
	case attConversationID:
		break;
	case attBody:
		default_handler(attribute, tsp+header, size);
		break;
	case attPriority:
		break;
	case attAttachData:
		attach_size=size;
		attach_loc =(int)tsp+header;
		if (SaveData && strlen(attach_title)>0 && attach_size > 0) {
			if (!save_attach_data(attach_title, (uint8 *)attach_loc,attach_size))
			{
				if (_TNEF_verbose) fprintf(stdout,"Decoding %s\n", attach_title);
			}
		}
		break;
	case attAttachTitle:
		strncpy(attach_title, make_string(tsp+header,size),255);
		if (SaveData && strlen(attach_title)>0 && attach_size > 0) {
			if (!save_attach_data(attach_title, (uint8 *)attach_loc,attach_size))
			{
				if (_TNEF_verbose) fprintf(stdout,"Decoding %s\n", attach_title);
			}
		}
		break;
	case attAttachMetaFile:
		default_handler(attribute, tsp+header, size);
		break;
	case attAttachCreateDate:
		break;
	case attAttachModifyDate:
		break;
	case attDateModified:
		break;
	case attAttachTransportFilename:
		default_handler(attribute, tsp+header, size);
		break;
	case attAttachRenddata:
		attach_title[0]=0;
		attach_size=0;
		attach_loc=0;
		default_handler(attribute, tsp+header, size);
		break;
	case attMAPIProps:
		handle_props(tsp+header);
		break;
	case attRecipTable:
		default_handler(attribute, tsp+header, size);
		break;
	case attAttachment:
		default_handler(attribute, tsp+header, size);
		break;
	case attTnefVersion:
		{
			uint32 version;
			version = read_32(tsp+header);
			if (version == -1) return -1;
		}
		break;
	case attOemCodepage:
		default_handler(attribute, tsp+header, size);
		break;
	case attOriginalMessageClass:
		break;
	case attOwner:
		default_handler(attribute, tsp+header, size);
		break;
	case attSentFor:
		default_handler(attribute, tsp+header, size);
		break;
	case attDelegate:
		default_handler(attribute, tsp+header, size);
		break;
	case attDateStart:
		break;
	case attDateEnd:
		break;
	case attAidOwner:
		default_handler(attribute, tsp+header, size);
		break;
	case attRequestRes:
		default_handler(attribute, tsp+header, size);
		break;
	default:
		default_handler(attribute, tsp+header, size);
		break;
	}
	return bytes;

}




/*------------------------------------------------------------------------
Procedure:     decode_tnef ID:1
Purpose:
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int TNEF_decode_tnef(uint8 *tnef_stream, int size)
{

	int ra_response;
	uint8 *tsp;

	if (_TNEF_debug) fprintf(stderr,"TNEF_decode_tnef: Start. Size = %d\n",size);

	// TSP == TNEF Stream Pointer (well memory block actually!)
	//
	tsp = tnef_stream;

	// Read in the signature of this TNEF
	//
	if (TNEF_SIGNATURE == read_32(tsp))
	{
		if (_TNEF_debug) fprintf(stderr,"TNEF signature is good\n");
	}

	// Move tsp pointer along
	//
	tsp += sizeof(TNEF_SIGNATURE);

	if (_TNEF_debug)  fprintf(stderr,"TNEF Attach Key: %x\n",read_16(tsp));
	// Move tsp pointer along
	//
  	tsp += sizeof(uint16);

	// While we still have more bytes to process,
	//		go through entire memory block and extract
	//		all the required attributes and files
	//
	if (_TNEF_debug) fprintf(stderr,"TNEF - Commence reading attributes\n");
	while ((tsp - tnef_stream) < size)
	{
		if (_TNEF_debug) fprintf(stderr,"Offset = %d\n",tsp -tnef_home);
		ra_response = read_attribute(tsp);
		if ( ra_response > 0 )
		{
			tsp += ra_response;
		} else {

			// Must find out /WHY/ this happens, and, how to rectify the issue.

			tsp++;
			break;
		}
	}

	if (_TNEF_debug) fprintf(stderr,"TNEF - DONE.\n");

	return 0;
}






/*------------------------------------------------------------------------
Procedure:     TNEF_main ID:1
Purpose:       Decodes a given TNEF encoded file
Input:
Output:
Errors:
------------------------------------------------------------------------*/
int TNEF_main( char *filename )
{
	FILE *fp;
	struct stat sb;
	uint8 *tnef_stream;
	int size, nread;

	if (_TNEF_debug) fprintf(stderr,"TNEF_main: Start, decoding %s\n",filename);

	SaveData = TRUE;

	// Test to see if the file actually exists
	//
	if (stat(filename,&sb) == -1)
	{
		if (_TNEF_stderrlogging > 0) fprintf(stderr,"Error stating file %s (%s)\n", filename,strerror(errno));
		if (_TNEF_syslogging > 0) LOGGER_log("TNEF_main: Error stating file %s (%s)\n", filename,strerror(errno));
		return -1;
	}

	// Get the filesize
	//
	size = sb.st_size;

	// Allocate enough memory to read in the ENTIRE file
	// FIXME - This could be a real consumer if multiple
	// instances of TNEF decoding is going on
	//
	tnef_home = tnef_stream = (uint8 *)malloc(size);
	tnef_limit = tnef_home +size;

	// If we were unable to allocate enough memory, then we
	// should report this
	//
	if (tnef_stream == NULL)
	{
		if (_TNEF_stderrlogging > 0)  fprintf(stderr,"Error allocating %d bytes for loading file (%s)\n", size,strerror(errno));
		if (_TNEF_syslogging > 0) LOGGER_log("TNEF_main: Error allocating %d bytes for loading file (%s)\n", size,strerror(errno));
		return -1;
	}

	// Attempt to open up the TNEF encoded file... if it fails
	// 	then report the failed condition to syslog
	//
	if ((fp = fopen(filename,"r")) == NULL)
	{
		if (_TNEF_stderrlogging > 0)  fprintf(stderr,"Error opening file %s for reading (%s)\n", filename,strerror(errno));
		if (_TNEF_syslogging > 0) LOGGER_log("TNEF_main: Error opening file %s for reading (%s)\n", filename,strerror(errno));
		return -1;
	}

	// Attempt to read in the entire file
	//
	nread = fread(tnef_stream, sizeof(uint8), size, fp);

	if (_TNEF_debug) fprintf(stderr,"TNEF: Read %d bytes\n",nread);

	// If we did not read in all the bytes, then let syslogs know!
	//
	if (nread < size)
	{
		if (_TNEF_syslogging > 0) LOGGER_log("TNEF_main: Error reading stream from file %s (%s)\n",filename,strerror(errno));
		return -1;
	}

	// Close the file
	//
	fclose(fp);

	// Proceed to decode the file
	//
	TNEF_decode_tnef(tnef_stream,size);


	if (_TNEF_debug) fprintf(stderr,"TNEF - finished decoding.\n");

	return 0;
}


//--------------------------END.


