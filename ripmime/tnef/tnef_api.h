// API for external programs wanting to use TNEF decoding
//
#ifndef __TNEF_API__
#define __TNEF_API__

int TNEF_main( char *filename );
int TNEF_set_verbosity( int level );
int TNEF_set_debug( int level );
int TNEF_set_syslogging( int level );
int TNEF_set_stderrlogging( int level );
int TNEF_set_path( char *path );
#endif


