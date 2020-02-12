# Makefile for acltool

CFLAGS=-g -Wall -I/usr/local/include
LIBS=-L/usr/local/lib -R/usr/local/lib -lreadline

OBJS=acltool.o argv.o buffer.o aclcmds.o commands.o misc.o

all: acltool

acltool.o: 	acltool.c acltool.h argv.h misc.h commands.h
argv.o: 	argv.c argv.h buffer.h misc.h
buffer.o: 	buffer.c buffer.h
misc.o:		misc.c misc.h
commands.o:	commands.c commands.h misc.h
aclcmds.o:	aclcmds.c aclcmds.h commands.h acltool.h

acltool: $(OBJS)
	$(CC) -o acltool $(OBJS) $(LIBS)

clean:
	-rm -f *~ *.o \#* core *.core acltool

push: 	clean
	git add -A && git commit -a && git push

pull:	clean
	git pull
