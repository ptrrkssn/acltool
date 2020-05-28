# Makefile for acltool

DEST=/usr/local
DESTBIN=$(DEST)/bin

# Change this to point to the libsmbclient (Samba) files if you want SMB support
SMBDIR=/usr/local/samba
#SMBDIR=/usr/local/samba/default
SMBDIR=/liu/pkg/samba/default

SMBINC=$(SMBDIR)/include
SMBLIB=$(SMBDIR)/lib

TESTDIR=t

ALIASES=lac sac edac

# Solaris
SOLCC=gcc

# CC=gcc
CFLAGS=-O -g -Wall
LDFLAGS=-lreadline

OBJS=gacl.o gacl_impl.o acltool.o argv.o buffer.o aclcmds.o basic.o commands.o misc.o opts.o strings.o range.o common.o cmd_edit.o vfs.o smb.o

auto build:
	@if [ -f "$(SMBLIB)/libsmbclient.so" -a -f "$(SMBINC)/libsmbclient.h" ]; then \
		$(MAKE) CFLAGS="$(CFLAGS) -I$(SMBINC) -DENABLE_SMB=1" LDFLAGS="$(LDFLAGS) -Wl,-rpath,$(SMBLIB) -L$(SMBLIB) -lsmbclient" `uname -s` ; \
	elif pkg-config --exists smbclient 2>/dev/null ; then \
		$(MAKE) CFLAGS="$(CFLAGS) `pkg-config --cflags smbclient` -DENABLE_SMB=1" LDFLAGS="$(LDFLAGS) `pkg-config --libs smbclient`" `uname -s` ; \
	else \
		$(MAKE) `uname -s`; \
	fi

help:
	@echo "USAGE: make <target>";echo "";echo "TARGETS: help, auto, linux, freebsd, solaris, macos, clean" ; exit 0

SunOS solaris omnios illumos:
	@$(MAKE) CC="$(SOLCC)" CFLAGS="$(CFLAGS) -I/usr/local/include" LDFLAGS="-L/usr/local/lib -R/usr/local/lib -lcurses $(LDFLAGS)" all

Linux linux:
	@$(MAKE) CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" all

FreeBSD freebsd:
	@$(MAKE) CC="$(CC)" CFLAGS="-I/usr/local/include $(CFLAGS)" LDFLAGS="-L/usr/local/lib -R/usr/local/lib -lncurses $(LDFLAGS)" all

Darwin macos:
	@$(MAKE) CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" all


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
gacl.o:		gacl.c gacl.h
gacl_impl.o:	gacl_impl.c gacl_impl.h


acltool: $(OBJS)
	$(CC) -o acltool $(OBJS) $(LDFLAGS)

distclean clean:
	-rm -f *~ *.o \#* core *.core acltool */*~
	-rm -fr t/*

push: 	clean
	git add -A && git commit -a && git push

pull:
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
	./acltool edac -vp -e '/user:nobody:r.*/d' t

distcheck: check
