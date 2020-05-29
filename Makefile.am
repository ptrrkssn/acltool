bin_PROGRAMS = acltool
acltool_SOURCES = gacl.c gacl_impl.c error.c acltool.c argv.c buffer.c aclcmds.c basic.c commands.c misc.c opts.c strings.c range.c common.c cmd_edit.c vfs.c smb.c
acltool_CFLAGS = $(READLINE_CFLAGS)
acltool_LDADD = $(READLINE_LIBS)

clean-local:
	-rm -f *~ \#* core

push: 	clean
	git add -A && git commit -a && git push

pull:
	git pull

