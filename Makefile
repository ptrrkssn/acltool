# Makefile for acltool


PREFIX = /usr/local
EXEC_PREFIX = ${prefix}
BINDIR = ${exec_prefix}/bin
mandir = ${datarootdir}/man
man1dir = $(mandir)/man1
datadir = ${datarootdir}
datarootdir = ${prefix}/share

CC = gcc
CPP = gcc -E

PKG_CONFIG = /usr/local/bin/pkg-config
PKG_CONFIG_LIBDIR = 
PKG_CONFIG_PATH = 

LIBSMBCLIENT_CFLAGS = 
LIBSMBCLIENT_LIBS = 

READLINE_CFLAGS = 
READLINE_LIBS = -lreadline -lncurses

INSTALL=/usr/bin/install -c

PACKAGE=acltool
VERSION=1.14

CPPFLAGS =  $(READLINE_CFLAGS) $(LIBSMBCLIENT_CFLAGS)
CFLAGS = -Wall -g -O2 $(READLINE_CFLAGS) $(LIBSMBCLIENT_CFLAGS)
LDFLAGS = 
LIBS =  $(READLINE_LIBS) $(LIBSMBCLIENT_LIBS)

TESTDIR=t

PROGRAMS=acltool

ACLTOOL_ALIASES=lac sac edac

ACLTOOL_OBJS=gacl.o gacl_impl.o error.o acltool.o argv.o buffer.o aclcmds.o basic.o commands.o misc.o opts.o strings.o range.o common.o cmd_edit.o vfs.o smb.o



all: $(PROGRAMS)


acltool.h:	vfs.h gacl.h argv.h commands.h aclcmds.h basic.h strings.h misc.h opts.h common.h smb.h error.h nfs4.h
acltool.o: 	acltool.c acltool.h
argv.o: 	argv.c argv.h acltool.h
opts.o: 	opts.c opts.h acltool.h
buffer.o: 	buffer.c buffer.h acltool.h
misc.o:		misc.c misc.h acltool.h
strings.o:	strings.c strings.h acltool.h
commands.o:	commands.c commands.h acltool.h
basic.o:	basic.c basic.h acltool.h
aclcmds.o:	aclcmds.c aclcmds.h acltool.h
error.o:	error.c error.h
gacl.o:		gacl.c gacl.h
gacl_impl.o:	gacl_impl.c gacl_impl.h


acltool: $(ACLTOOL_OBJS)
	$(CC) $(LDFLAGS) -o acltool $(ACLTOOL_OBJS) $(LIBS)

distclean: clean
	rm -fr config.status config.log .deps autom4te.cache

clean:
	-rm -f *~ *.o \#* core *.core acltool */*~
	-rm -fr t/*


push: 	distclean
	git add -A && git commit -a && git push

pull:
	git pull


install: $(PROGRAMS) install-aliases
	$(INSTALL) -m755 acltool $(BINDIR)

install-aliases: acltool
	for A in $(ACLTOOL_ALIASES); do ln -sf acltool $(BINDIR)/$$A; done


check:
	@mkdir -p $(TESTDIR) && $(MAKE) check-`uname -s`

check-macos check-Darwin: check-all

check-freebsd check-FreeBSD: check-all

check-sunos check-solaris check-omnios check-illumos check-SunOS: check-all

check-linux check-Linux:
	-@df -t nfs4 $(TESTDIR) 2>/dev/null && $(MAKE) check-all

check-all: check-lac check-sac check-edac

check-lac: acltool
	./acltool lac t

check-sac: acltool
	./acltool sac -vp "user:nobody:rwx,user:$$USER:all" t

check-edac: acltool
	./acltool edac -vp -e '/user:nobody:r.*/d' t

distcheck:
	@echo "Nothing to do"
