# Makefile for acltool

CFLAGS=-O -g -Wall -I/usr/local/include
LIBS=-L/usr/local/lib -R/usr/local/lib -lreadline

OBJS=acltool.o argv.o buffer.o aclcmds.o basic.o commands.o misc.o opts.o strings.o

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

acltool: $(OBJS)
	$(CC) -o acltool $(OBJS) $(LIBS)

clean:
	-rm -f *~ *.o \#* core *.core acltool

push: 	clean
	git add -A && git commit -a && git push

pull:	clean
	git pull
