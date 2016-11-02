##
## This file is part of the swodec project.
##
## Copyright (C) 2016 Marc Schink <swo-dev@marcschink.de>
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

# serial 20161102

## _SWODEC_SET_PACKAGE_VERSION(prefix, version, major, minor, micro)
##
m4_define([_SWODEC_SET_PACKAGE_VERSION], [
	m4_assert([$# == 5])

	# Get the short Git revision hash of the current commit.
	git_version=`git --git-dir="$srcdir/.git" rev-parse \
		--short HEAD 2> /dev/null`

	# Try to get the release tag for the package version from the current
	# commit.
	tag=`git --git-dir="$srcdir/.git" describe --match "$2" \
		--exact-match 2> /dev/null`

	version=$2

	# If Git is available, append the short Git revision hash of the
	# current commit to the version string if there is no release tag for
	# the package version on it.
	AS_IF([test -n "$git_version" && test -z "$tag"],
		[version="$version-git-$git_version"])

	AC_SUBST([$1_MAJOR], [$3])
	AC_SUBST([$1_MINOR], [$4])
	AC_SUBST([$1_MICRO], [$5])
	AC_SUBST([$1], [$version])
])

## SWODEC_SET_PACKAGE_VERSION(prefix, version)
##
## Parse the package version string of the format <major>.<minor>.<micro> and
## set the variables <prefix>_{MAJOR,MINOR,MICRO} to their corresponding
## values.
##
## Set the variable <prefix> to the package version string. If Git is
## available, append the short Git revision hash of the current commit to the
## version string if there is no release tag for the package version on it.
##
AC_DEFUN([SWODEC_SET_PACKAGE_VERSION], [
	m4_assert([$# == 2])

	_SWODEC_SET_PACKAGE_VERSION([$1], [$2],
		m4_unquote(m4_split(m4_expand([$2]), [\.])))
])
