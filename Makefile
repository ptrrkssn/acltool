# Makefile for acltool

DEST=/usr/local
DESTBIN=$(DEST)/bin

TESTDIR=t

ALIASES=lac sac edac

# CC=gcc
SOLARIS_CC=gcc
CFLAGS=-O -g -Wall
DEBUG_CFLAGS=-g -Wall

CMDOBJS=common.o cmd_edit.o vfs.o
OBJS=gacl.o acltool.o argv.o buffer.o aclcmds.o basic.o commands.o misc.o opts.o strings.o range.o $(XOBJS) $(CMDOBJS)
LIBS=$(XLDFLAGS) -lreadline $(XLIBS) 

auto build:
	@$(MAKE) `uname -s`

debug:
	@$(MAKE) `uname -s` CFLAGS="$(DEBUG_CFLAGS)"

help:
	@echo "USAGE: make <target>";echo "";echo "TARGETS: help, auto, linux, freebsd, solaris, clean" ; exit 0

SunOS solaris omnios illumos:
	@$(MAKE) CC="$(SOLARIS_CC)" CFLAGS="$(CFLAGS) -I/usr/local/include" XLIBS="-L/usr/local/lib -R/usr/local/lib -lcurses" all

Linux linux:
	@$(MAKE) CC="$(CC)" CFLAGS="$(CFLAGS)" all

FreeBSD freebsd:
	@$(MAKE) CC="$(CC)" CFLAGS="-I/usr/local/include $(CFLAGS)" XLDFLAGS="-L/usr/local/lib -R/usr/local/lib" XLIBS="-lncurses" all

macos Darwin:
	@$(MAKE) CC="$(CC)" CFLAGS="$(CFLAGS)" all

all: acltool

acltool.o: 	acltool.c acltool.h argv.h misc.h commands.h strings.h
argv.o: 	argv.c argv.h buffer.h misc.h strings.h
opts.o: 	opts.c opts.h misc.h strings.h

buffer.o: 	buffer.c buffer.h
misc.o:		misc.c misc.h strings.h
strings.o:	strings.c strings.h

commands.o:	commands.c commands.h misc.h strings.h
basic.o:	basic.c    basic.h    commands.h
aclcmds.o:	aclcmds.c  aclcmds.h  commands.h acltool.h strings.h

gacl.o:		gacl.c gacl.h


acltool: $(OBJS)
	$(CC) -o acltool $(OBJS) $(LIBS)

distclean clean:
	-rm -f *~ *.o \#* core *.core acltool */*~
	-rm -fr t/*

push: 	clean
	git add -A && git commit -a && git push

pull:	clean
	git pull

install:	acltool
	cp acltool $(DESTBIN) && cd $(DESTBIN) && for A in $(ALIASES); do ln -sf acltool $$A; done

check:
	@mkdir -p $(TESTDIR) && $(MAKE) check-`uname -s`

check-macos check-Darwin: check-all

check-freebsd check-FreeBSD: check-all

check-sunos check-solaris check-omnios check-illumos check-SunOS: check-all

check-linux check-Linux:
	-@df -t nfs4 $(TESTDIR) 2>/dev/null && $(MAKE) check-all

check-all: check-lac check-sac check-edac

check-lac: auto
	./acltool lac t

check-sac: auto
	./acltool sac -vp "user:nobody:rwx,user:$$USER:all" t

check-edac: auto
	./acltool edac -vpRe '/user:nobody:r.*/d' t

distcheck: check
