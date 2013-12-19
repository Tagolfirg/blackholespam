
/* MIME.h */

/* Exit Error codes */
#define _EXITERR_UNDEFINED_BOUNDARY 100
#define _EXITERR_PRINT_QUOTABLE_INPUT_NOT_OPEN 200
#define _EXITERR_PRINT_QUOTABLE_OUTPUT_NOT_OPEN 201
#define _EXITERR_BASE64_OUTPUT_NOT_OPEN 210
#define _EXITERR_BASE64_UNABLE_TO_OUTPUT 211
#define _EXITERR_MIMEREAD_CANNOT_OPEN_OUTPUT 220
#define _EXITERR_MIMEREAD_CANNOT_WRITE_OUTPUT 221
#define _EXITERR_MIMEUNPACK_CANNOT_OPEN_INPUT_FILE 230
#define _EXITERR_MIMEUNPACK_CANNOT_OPEN_HEADERS_FILE 231

#define _MIME_RENAME_METHOD_INFIX 1
#define _MIME_RENAME_METHOD_PREFIX 2
#define _MIME_RENAME_METHOD_POSTFIX 3

#define _MIME_STRLEN_MAX 1023

/* Debug levels */
#define _MIME_DEBUG_PEDANTIC 10
#define _MIME_DEBUG_NORMAL 1

int MIME_clean_filename( char *fname );
int MIME_read( char *mpname ); /* returns filesize in KB */
int MIME_unpack( char *unpackdir, char *mpname, int current_recusion_level );
int MIME_unpack_single( char *unpackdir, char *mpname, int current_recusion_level );
int MIME_unpack_mailbox( char *unpackdir, char *mpname, int current_recursion_level );
int MIME_insert_Xheader( char *fname, char *xheader );
int MIME_set_blankfileprefix( char *prefix );
int MIME_set_verbosity( int level );
int MIME_set_debug( int level );
int MIME_set_dumpheaders( int level );
int MIME_set_headersname( char *fname );
int MIME_set_syslogging( int level );
int MIME_set_stderrlogging( int level );
int MIME_set_no_nameless( int level );
int MIME_set_uniquenames( int level );
int MIME_set_renamemethod( int method );
int MIME_set_noparanoid( int level );
int MIME_set_mailboxformat( int level );
int MIME_set_webform( int level );
int MIME_get_attachment_count( void );
char *MIME_get_blankfileprefix( void );
char *MIME_get_headersname( void );
int MIME_decode_text_line( char *line );
int MIME_init( void );
int MIME_close( void );
int MIME_set_tmpdir( char *tmpdir );
int MIME_set_no_uudecode( int level );
//int MIME_decode_TNEF( FILE *f, char *unpackdir, struct _header_info *hinfo, int keep );



