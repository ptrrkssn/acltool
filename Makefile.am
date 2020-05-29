bin_PROGRAMS = acltool

man1_MANS = acltool.man

acltool_SOURCES = gacl.c gacl_impl.c error.c acltool.c argv.c buffer.c aclcmds.c basic.c commands.c misc.c opts.c strings.c range.c common.c cmd_edit.c vfs.c smb.c aclcmds.h basic.h common.h gacl.h opts.h strings.h acltool.h buffer.h error.h misc.h range.h vfs.h argv.h commands.h gacl_impl.h nfs4.h smb.h

acltool_CFLAGS = $(READLINE_CFLAGS) $(LIBSMBCLIENT_CFLAGS)
acltool_LDADD = $(READLINE_LIBS) $(LIBSMBCLIENT_LIBS)

clean-local:
	-rm -f *~ \#* core

push: maintainer-clean
	$(MAKE) -f Makefile.dist push

pull:
	git pull
