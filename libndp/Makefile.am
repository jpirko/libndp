MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -fvisibility=hidden -ffunction-sections -fdata-sections
AM_LDFLAGS = -Wl,--gc-sections -Wl,--as-needed

lib_LTLIBRARIES = libndp.la
libndp_la_SOURCES = libndp.c
libndp_la_CFLAGS= $(AM_CFLAGS) -I${top_srcdir}/include -D_GNU_SOURCE
libndp_la_LDFLAGS = $(AM_LDFLAGS) -version-info @LIBNDP_CURRENT@:@LIBNDP_REVISION@:@LIBNDP_AGE@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libndp.pc

EXTRA_DIST = ndp_private.h list.h
