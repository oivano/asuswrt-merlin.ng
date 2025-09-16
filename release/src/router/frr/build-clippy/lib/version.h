/* lib/version.h.  Generated from version.h.in by configure.
 *
 * Quagga version
 * Copyright (C) 1997, 1999 Kunihiro Ishiguro
 * 
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef _ZEBRA_VERSION_H
#define _ZEBRA_VERSION_H

#ifdef GIT_VERSION
#include "gitversion.h"
#endif

#ifndef GIT_SUFFIX
#define GIT_SUFFIX ""
#endif
#ifndef GIT_INFO
#define GIT_INFO ""
#endif

#define FRR_PAM_NAME    "frr"
#define FRR_SMUX_NAME   "frr"
#define FRR_PTM_NAME    "frr"

#define FRR_FULL_NAME   "FRRouting"
#define FRR_VERSION     "6.0.3" GIT_SUFFIX
#define FRR_VER_SHORT   "6.0.3"
#define FRR_BUG_ADDRESS "https://github.com/frrouting/frr/issues"
#define FRR_COPYRIGHT   "Copyright 1996-2005 Kunihiro Ishiguro, et al."
#define FRR_CONFIG_ARGS "'--enable-clippy-only' '--disable-nhrpd' '--disable-bfdd' '--disable-vtysh' 'PKG_CONFIG_PATH=/usr/local/lib/pkgconfig' 'LIBS=-ljson-c -lpython3.8 -ldl -lm'"

#define FRR_DEFAULT_MOTD \
	"\n" \
	"Hello, this is " FRR_FULL_NAME " (version " FRR_VERSION ").\n" \
	FRR_COPYRIGHT "\n" \
	GIT_INFO "\n"

pid_t pid_output (const char *);

#endif /* _ZEBRA_VERSION_H */
