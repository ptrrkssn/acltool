# Makefile for acltool

DEST=/usr/local
DESTBIN=$(DEST)/bin

# Change this to point to the libsmbclient (Samba) files if you want SMB support
#SMBDIR=/usr/local/samba/default
SMBDIR=/liu/pkg/samba/default
SMBINC=$(SMBDIR)/include
SMBLIB=$(SMBDIR)/lib

# Remove comment '#' character to enable SMB
SMB_CFLAGS=-I$(SMBINC) -DENABLE_SMB=1
SMB_LDFLAGS=-L$(SMBLIB) -Wl,-rpath,$(SMBLIB) -lsmbclient


TESTDIR=t

ALIASES=lac sac edac

# CC=gcc
SOLARIS_CC=gcc
CFLAGS=-O -g -Wall $(SMB_CFLAGS)
DEBUG_CFLAGS=-g -Wall

CMDOBJS=common.o cmd_edit.o vfs.o smb.o
OBJS=gacl.o acltool.o argv.o buffer.o aclcmds.o basic.o commands.o misc.o opts.o strings.o range.o $(XOBJS) $(CMDOBJS)
LIBS=$(XLDFLAGS) -lreadline $(XLIBS) $(SMB_LDFLAGS)

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

acltool.h:	vfs.h gacl.h argv.h commands.h aclcmds.h basic.h strings.h misc.h opts.h common.h smb.h nfs4.h Makefile

acltool.o: 	acltool.c acltool.h
argv.o: 	argv.c argv.h acltool.h
opts.o: 	opts.c opts.h acltool.h
buffer.o: 	buffer.c buffer.h acltool.h
misc.o:		misc.c misc.h acltool.h
strings.o:	strings.c strings.h acltool.h
commands.o:	commands.c commands.h acltool.h
basic.o:	basic.c basic.h acltool.h
aclcmds.o:	aclcmds.c aclcmds.h acltool.h
gacl.o:		gacl.c gacl.h acltool.h


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
