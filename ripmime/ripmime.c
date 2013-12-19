/*----------------------------------------
 * ripMIME -
 *
 * Written by Paul L Daniels
 * pldaniels@pldaniels.com
 *
 * (C)2001 P.L.Daniels
 * http://www.pldaniels.com/ripmime
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "mime.h"
#include "tnef/tnef_api.h"
#include "MIME_headers_api.h"


char defaultdir[]=".";
char version[]="v1.2.16.18 - 12/10/2002 (C) PLDaniels http://www.pldaniels.com/ripmime";
char help[]="ripMIME -i <mime file> -d <directory>\
 [-p prefix] [-e [header file]] [-vVh] [--syslog_on] [--stderr_off]\
 [--no_nameless] [--unique_names [--prefix|--postfix|--infix]]\
 [--no_paranoid] [--mailbox] [--debug]\n\
	Options available :\n\
	-i : Input MIME encoded file (use '-' to input from STDIN)\n\
	-d : Output directory\n\
	-p : Specify prefix filename to be used on files without a filename (default 'text')\n\
	-e [headers file name] : Dump headers from mailpack (default '_headers_')\n\
	-v : Turn on verbosity\n\
	--syslog_on : Turn on syslog'ing (default is OFF)\n\
	--stderr_off : Turn off stderr logging (default is ON)\n\
	--no_paranoid : Turns off strict ascii-alnum filenaming\n\
	--no_nameless : Do not save nameless attachments\n\
	--unique_names : Dont overwrite existing files\n\
	 --prefix : rename by putting unique code at the front of the filename\n\
	 --postfix : rename by putting unique code at the end of the filename\n\
	 --infix : rename by putting unique code in the middle of the filename\n\
	--mailbox : Process mailbox file\n\
	--debug : Produces detailed information about the whole decoding process\n\
	--no_uudecode : Turns off the facility of detecting UUencoded attachments in emails\n\
	-V : Give version information\n\
	-h : This message (help)\n\n\n";



/*------------------------------------------------------------------------
 Procedure:     main ID:1
 Purpose:       The main function... the start of everything
 Input:
 Output:
 Errors:
------------------------------------------------------------------------*/
int main( int argc, char **argv )
{

	char *dir = defaultdir, *inputfile=NULL;
	int i=0, result=0;

	/* if the user has just typed in "ripmime" and nothing else, then we had better give them
	 * the rundown on how to use this program */

	if (argc < 2)
	{
		fprintf(stderr,"%s\n%s",version,help);
		exit(1);
	}



	// determine our arguments

	for (i = 1; i < argc; i++)
	{
		// if the first char of the argument is a '-', then we possibly have a flag

		if (argv[i][0] == '-')
		{
			// test the 2nd char of the parameter

			switch (argv[i][1])
			{
				case 'i': i++; inputfile = argv[i]; break;
				case 'd': i++; dir = argv[i]; break;
				case 'p': i++; MIME_set_blankfileprefix(argv[i]); break; // this is in mime.h
				case 'e': MIME_set_dumpheaders(1);
					if ( (i < (argc-1))&&(argv[i+1][0] != '-')) MIME_set_headersname(argv[++i]);
					break; // makes MIME dump out the headers to a file

				case 'v':
					MIME_set_verbosity(1);
					TNEF_set_verbosity(1);
					MIMEH_set_verbosity(1);
					break;

				case 'V': fprintf(stdout,"%s\n",version); exit(1); break;
				case 'h': fprintf(stderr,"%s\n",help); exit(1); break;

				// if we get ANOTHER - symbol, then we have an extended flag

				case '-':
					if (strncmp(&(argv[i][2]),"no_paranoid",11) == 0) { MIME_set_noparanoid(1); }
					else
					if (strncmp(&(argv[i][2]),"prefix",6) == 0 ) { MIME_set_renamemethod(_MIME_RENAME_METHOD_PREFIX); }
					else
					if (strncmp(&(argv[i][2]),"postfix",7) == 0 ) { MIME_set_renamemethod(_MIME_RENAME_METHOD_POSTFIX); }
					else
					if (strncmp(&(argv[i][2]),"infix",5) == 0 ) { MIME_set_renamemethod(_MIME_RENAME_METHOD_INFIX); }
					else
					if (strncmp(&(argv[i][2]),"unique_names",12) == 0 ) { MIME_set_uniquenames(1); }
					else
					if (strncmp(&(argv[i][2]),"syslog_on",9) == 0) { MIME_set_syslogging(1); }
					else
					if (strncmp(&(argv[i][2]),"stderr_off",10) == 0) { MIME_set_stderrlogging(0); }
					else
					if (strncmp(&(argv[i][2]),"no_nameless",11) == 0) { MIME_set_no_nameless(1); }
					else
					if (strncmp(&(argv[i][2]),"debug",5) == 0) { MIME_set_debug(1);}
					else
					if (strncmp(&(argv[i][2]),"mailbox",7) == 0) { MIME_set_mailboxformat(1); }
					else
					if (strncmp(&(argv[i][2]),"no_uudecode",7) == 0) { MIME_set_no_uudecode(1); }
//					else
//					if (strncmp(&(argv[i][2]),"webform",7) == 0) { MIME_set_webform(1); }
					else {
						fprintf(stderr, "Cannot interpret option \"%s\"\n%s\n",argv[i],help);exit(1);break;
						}
					break;

				// else, just dump out the help message

				default : fprintf(stderr, "Cannot interpret option \"%s\"\n%s\n",argv[i],help);exit(1);break;

				} // Switch argv[i][1]
			} // if argv[i][0] == -
		} // for

	// if our input filename wasn't specified, then we better let the user know!

	if (!inputfile)
	{
		fprintf(stderr,"Error: No input file was specified\n");
		exit(1);
	}

	// Fire up the randomizer

	srand(time(NULL));

	// clean up the output directory name if required (remove any trailing /'s, as suggested by James Cownie 03/02/2001

	if (dir[strlen(dir)-1] == '/')  { dir[strlen(dir)-1] = '\0'; }

	// Create the output directory required as specified by the -d parameter

	if (dir != defaultdir)
	{
		result = mkdir(dir,S_IRWXU);

		// if we had a problem creating a directory, and it wasn't just
		// due to the directory already existing, then we have a bit of
		// a problem on our hands, hence, report it.
		//

		if ((result == -1)&&(errno != EEXIST))
		{
			fprintf(stderr,"ripMIME: Cannot create directory '%s' (%s)\n",dir,strerror(errno));
			return -1;
		}
	}

	// Unpack the contents

	MIMEH_set_outputdir( dir );
	MIME_init();
	MIME_unpack( dir, inputfile, 0);

	// do any last minute things

	MIME_close();

	return 0;

	}

/*-END-----------------------------------------------------------*/
