#
# Autoconf macro definitions for the session manager server.
#
# Copyright (C) 2018-2019 J.M. Heisz.  All Rights Reserved.
# See the LICENSE file accompanying the distribution your rights to use
# this software.
#

####### Part A - Standard Autoconf Header Elements #######

AC_REVISION(0.1.0)dnl

# Standard initialization sequence defines package details
AC_INIT([nginx-manager], [0.1.0])
# Secret location for the standard configuration scripts
AC_CONFIG_AUX_DIR(configure-scripts)
AM_INIT_AUTOMAKE
AC_MSG_RESULT([Configuring nginx session manager - version 0.1.0])
AM_CONFIG_HEADER(config.h)

# Uses libtool notation for sub-library compilation
AM_PROG_AR
LT_INIT

# Choose a working default prefix
dtag=`date "+%y%m%d%H%M%S"`
ac_default_prefix="/tmp/wrdg-tk-${dtag}"
year=`date "+%G"`

# Configure the automake system and target host instance
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CANONICAL_HOST

####### Part B - Build/Compilation/Release Tool Determination #######

# Standard subdirectory make and compilation tests
AC_PROG_MAKE_SET
AC_PROG_CC

####### Part C - Target and Build Type Determination #######

configDate=`date "+%Y-%m-%d %T"`
AC_DEFINE_UNQUOTED([CONFIGUREDATE], ["$configDate"],
                   [Configuration/build date for version display])

# Define current year for copyright purposes
AC_DEFINE_UNQUOTED([CURRENT_YEAR], ["$year"],
                   [Current year used for copyright])

# Support build labelling
AC_ARG_WITH(label,
[  --with-label            provide an explicit label for this build ],
[
    AC_DEFINE_UNQUOTED([BUILDLABEL], ["Label: \"${withval}\"\\n"],
                       [Explicit label associated with the build])
],
[
    AC_DEFINE_UNQUOTED([BUILDLABEL], [""],
                       [Empty placeholder for label associated with the build])
])

####### Part D - Dependent Product/Library Determination #######

####### Part E - System-Specific Headers/Libraries/Options #######

# Build config.h for header availability determination
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([endian.h])
AC_CHECK_HEADERS([sys/endian.h])
AC_CHECK_HEADERS([byteswap.h])
AC_CHECK_HEADERS([poll.h])
AC_CHECK_HEADERS([sys/epoll.h])

####### All Done - Generate Configuration Specific Files #######

AC_CONFIG_FILES([Makefile
                 src/Makefile
                ])
AC_OUTPUT
