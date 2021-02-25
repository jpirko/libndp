MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I${top_srcdir}/include -D_GNU_SOURCE

ndptool_LDADD = $(top_builddir)/libndp/libndp.la

bin_PROGRAMS=ndptool
ndptool_SOURCES=ndptool.c
