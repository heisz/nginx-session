#
# Makefile instance for the nginx session management daemon.
#
# Copyright (C) 2018-2019 J.M. Heisz.  All Rights Reserved.
# See the LICENSE file accompanying the distribution your rights to use
# this software.
#

# Just one outcome from this build
bin_PROGRAMS = manager

# Related inclusion locations and other options
AM_CPPFLAGS = -I.. -I../.. -I../toolkit \
              -I../toolkit/src/db \
              -I../toolkit/src/lang \
              -I../toolkit/src/network \
              -I../toolkit/src/utility \
              @MYSQL_INCLUDE@ @PGSQL_INCLUDE@

manager_SOURCES = manager.c requests.c \
                  ../toolkit/src/db/dbxf.c \
                  ../toolkit/src/lang/json.c \
                  ../toolkit/src/network/event.c \
                  ../toolkit/src/network/socket.c \
                  ../toolkit/src/utility/array.c \
                  ../toolkit/src/utility/buffer.c \
                  ../toolkit/src/utility/daemon.c \
                  ../toolkit/src/utility/hash.c \
                  ../toolkit/src/utility/log.c \
                  ../toolkit/src/utility/mem.c \
                  ../toolkit/src/utility/thread.c

# What a pain, can't do direct substitution in automake SOURCES
if INCLUDE_MYSQL_DRV
manager_SOURCES += ../toolkit/src/db/mysql/dbfmysql.c
endif

if INCLUDE_PGSQL_DRV
manager_SOURCES += ../toolkit/src/db/pgsql/dbfpgsql.c
endif

manager_LDADD = @MYSQL_LIB@ @PGSQL_LIB@ -lpthread -lm
manager_LDFLAGS = -static

# Removes the automake/autoconf generated files for ultra-clean source tree
MAINTAINERCLEANFILES = Makefile.in
