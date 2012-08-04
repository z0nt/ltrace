DIST_SUBDIRS = \
	amd64

SUBDIRS = \
	$(HOST_CPU)

noinst_LTLIBRARIES = \
	../libos.la

___libos_la_SOURCES = \
	events.c \
	trace.c \
	proc.c \
	breakpoint.c

___libos_la_LIBADD = \
	libcpu.la

noinst_HEADERS = \
	signalent1.h \
	syscallent1.h \
	trace.h

EXTRA_DIST = \
	mksignalent \
	mksyscallent

MAINTAINERCLEANFILES = \
	Makefile.in
