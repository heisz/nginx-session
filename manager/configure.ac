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
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AC_CANONICAL_HOST

####### Part B - Build/Compilation/Release Tool Determination #######

# Standard subdirectory make and compilation tests
AC_PROG_MAKE_SET
AM_PROG_CC_C_O
# AC_PROG_CC

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

# Determine if MySQL is available and provide associated definitions
AC_CHECK_PROGS(MYSQL_CONFIG, mysql_config)
if test -n "${MYSQL_CONFIG}"; then
    AC_DEFINE([HAVE_MYSQL_DB], [1],
              [Define to 1 if you have build support for MySQL client])
    MYSQL_SRCDIR="mysql"
    MYSQL_INCLUDE=`${MYSQL_CONFIG} --include`
    MYSQL_LIB=`${MYSQL_CONFIG} --libs`
    MYSQL_DRV_SRC="../toolkit/src/db/mysql/dbfmysql.c"
    AC_SUBST(MYSQL_SRCDIR)
    AC_SUBST(MYSQL_INCLUDE)
    AC_SUBST(MYSQL_LIB)
fi
AM_CONDITIONAL([INCLUDE_MYSQL_DRV], [ test -n "${MYSQL_CONFIG}" ])

# Determine if PostgreSQL is available and provide associated definitions
AC_CHECK_PROGS(PGSQL_CONFIG, pg_config)
if test -n "${MYSQL_CONFIG}"; then
    AC_DEFINE([HAVE_PGSQL_DB], [1],
              [Define to 1 if you have build support for PostgreSQL client])
    PGSQL_SRCDIR="pgsql"
    PGSQL_INCLUDE_DIR=`${PGSQL_CONFIG} --includedir`
    PGSQL_INCLUDE="-I${PGSQL_INCLUDE_DIR}"
    PGSQL_LIB_DIR=`${PGSQL_CONFIG} --libdir`
    PGSQL_LIB="-L${PGSQL_LIB_DIR} -lpq"
    AC_SUBST(PGSQL_SRCDIR)
    AC_SUBST(PGSQL_INCLUDE)
    AC_SUBST(PGSQL_LIB)
fi
AM_CONDITIONAL([INCLUDE_PGSQL_DRV], [ test -n "${PGSQL_CONFIG}" ])

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
