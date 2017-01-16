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

AC_INIT([swodec], [0.1.0], [swo-dev@marcschink.de])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([foreign -Wall -Werror])

# Enable additional compiler warnings via -Wall and -Wextra.
SWODEC_CFLAGS="-Wall -Wextra -Werror"

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Initialize pkg-config.
PKG_PROG_PKG_CONFIG

# Checks for libraries.

# Check for glib-2.0 which is always needed.
PKG_CHECK_MODULES([glib], [glib-2.0 >= 2.28.0])

# Check for libswo-0.1 which is always needed.
PKG_CHECK_MODULES([libswo], [libswo >= 0.1.0])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

SWODEC_SET_PACKAGE_VERSION([SWODEC_VERSION_PACKAGE], [AC_PACKAGE_VERSION])

# Use C99 compatible stdio functions on MinGW instead of the incompatible
# functions provided by Microsoft.
AS_CASE([$host_os], [mingw*],
	[AC_DEFINE([__USE_MINGW_ANSI_STDIO], [1],
		[Define to 1 to use C99 compatible stdio functions on MinGW.])])

AC_SUBST([SWODEC_CFLAGS])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([src/version.h])

AC_OUTPUT

echo
echo "swodec configuration summary:"
echo " - Package version ................ $SWODEC_VERSION_PACKAGE"
echo " - Installation prefix ............ $prefix"
echo " - Building on .................... $build"
echo " - Building for ................... $host"
echo
