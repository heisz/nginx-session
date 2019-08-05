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
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/.. -I$(top_srcdir)/toolkit \
              -I$(top_srcdir)/toolkit/src/lang \
              -I$(top_srcdir)/toolkit/src/network \
              -I$(top_srcdir)/toolkit/src/utility

manager_SOURCES = manager.c requests.c \
                  $(top_builddir)/toolkit/src/lang/json.c \
                  $(top_builddir)/toolkit/src/network/event.c \
                  $(top_builddir)/toolkit/src/network/socket.c \
                  $(top_builddir)/toolkit/src/utility/array.c \
                  $(top_builddir)/toolkit/src/utility/buffer.c \
                  $(top_builddir)/toolkit/src/utility/daemon.c \
                  $(top_builddir)/toolkit/src/utility/hash.c \
                  $(top_builddir)/toolkit/src/utility/log.c \
                  $(top_builddir)/toolkit/src/utility/mem.c \
                  $(top_builddir)/toolkit/src/utility/thread.c
manager_LDADD = -lpthread -lm
manager_LDFLAGS = -static

# Removes the automake/autoconf generated files for ultra-clean source tree
MAINTAINERCLEANFILES = config.cache config.log config.status Makefile.in \
                       aclocal.m4 configure libtool config.h.in
