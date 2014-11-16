##
## This file is part of the swodec project.
##
## Copyright (C) 2014 Marc Schink <swo-dev@marcschink.de>
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.
##

AC_PREREQ([2.69])

AC_INIT([swodec], [0.1.0], [BUG-REPORT-ADDRESS])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])

# Enable additional compiler warnings via -Wall and -Wextra.
CFLAGS="$CFLAGS -Wall -Wextra -Werror"

# Checks for programs.
AC_PROG_CC

# Initialize pkg-config.
PKG_PROG_PKG_CONFIG

# Checks for libraries.

# Check for glib-2.0 which is always needed.
PKG_CHECK_MODULES([glib], [glib-2.0 >= 2.28.0],
	[CFLAGS="$CFLAGS $glib_CFLAGS"; LIBS="$LIBS $glib_LIBS"])

# Check for libswo-0.1 which is always needed.
PKG_CHECK_MODULES([libswo], [libswo >= 0.1.0],
	[CFLAGS="$CFLAGS $libswo_CFLAGS"; LIBS="$LIBS $libswo_LIBS"])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])

AC_OUTPUT
