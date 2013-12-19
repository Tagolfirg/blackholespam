/* misc.h */
/*
   Copyright (C) 2002
        Chris Kennedy, The Groovy Organization.

   The Blackhole is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Blackhole is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   For a copy of the GNU Library General Public License
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  or go to http://www.gnu.org
*/
#ifndef _MISC_H
#define _MISC_H 1

#include <assert.h>
#ifndef USE_MCONFIG
#include "config.h"
#endif

int one_out(int, int, char *);

#define WITH_BH_ASSERT

/* preprocessor functions */
#ifdef WITH_BH_ASSERT
#define bh_assert(expr) \
        (expr) ? one_out(expr,__LINE__,id) : 0
#else
#define bh_assert(expr) \
	expr
#endif

#endif /* _MISC_H */
