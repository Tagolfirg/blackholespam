#ifndef __ZSTRNCPY__
#define __ZSTRNCPY__

char *zstrncpy( char *dst, const char *src, size_t len );
char *zstrncat( char *dst, const char *src, size_t len );
char *zstrncate( char *dst, const char *src, size_t len, char *endpoint );

#endif

