
#define _CTYPE_UNSPECIFIED -1
#define _CTYPE_MULTIPART 100
#define _CTYPE_MULTIPART_MIXED 101
#define _CTYPE_TEXT 200
#define _CTYPE_TEXT_PLAIN 201
#define _CTYPE_TEXT_UNKNOWN 202
#define _CTYPE_IMAGE 300
#define _CTYPE_IMAGE_PNG 303
#define _CTYPE_OCTECT 400
#define _CTYPE_RFC822 500
#define _CTYPE_TNEF 600
#define _CTYPE_UNKNOWN 0

#define _CTRANS_ENCODING_UNSPECIFIED -1
#define _CTRANS_ENCODING_B64 100
#define _CTRANS_ENCODING_7BIT 101
#define _CTRANS_ENCODING_8BIT 102
#define _CTRANS_ENCODING_QP 103
#define _CTRANS_ENCODING_RAW 104
#define _CTRANS_ENCODING_UUENCODE 105
#define _CTRANS_ENCODING_UNKNOWN 0

#define _CDISPOSITION_UNSPECIFIED -1
#define _CDISPOSITION_INLINE 100
#define _CDISPOSITION_ATTACHMENT 200
#define _CDISPOSITION_FORMDATA 300
#define _CDISPOSITION_UNKNOWN 0

#define _MIMEH_FOUND_FROM 100

#define _MIMEH_STRLEN_MAX 1023
#define _MIMEH_FILENAMELEN_MAX 128

#define _MIMEH_DEBUG_NORMAL 1
#define _MIMEH_DEBUG_PEDANTIC 10

struct _header_info
{
	char scratch[_MIMEH_STRLEN_MAX +1];
	int content_type;
	char boundary[_MIMEH_STRLEN_MAX +1];
	int boundary_located;
	char filename[_MIMEH_FILENAMELEN_MAX +1];
	char name[_MIMEH_STRLEN_MAX +1];
	int content_transfer_encoding;
	int content_disposition;
	int charset;
	int format;
	int file_has_uuencode;
	char uudec_name[_MIMEH_FILENAMELEN_MAX +1];	// UUDecode name. This is a post-decode information field.
	int current_recursion_level;

};


extern int MIMEH_doubleCR;
extern char MIMEH_doubleCRname[_MIMEH_STRLEN_MAX +1];

int MIMEH_set_debug( int level );
int MIMEH_set_verbosity( int level );
int MIMEH_set_mailbox( int level );
int MIMEH_set_headers_save( FILE *f );
int MIMEH_set_headers_nosave( void );
int MIMEH_get_headers_save( void );
int MIMEH_read_headers( FFGET_FILE *f );
int MIMEH_parse_headers( FFGET_FILE *f, struct _header_info *hinfo );
int MIMEH_display_info( struct _header_info *hinfo );
int MIMEH_set_webform( int level );
int MIMEH_set_outputdir( char *dir );


