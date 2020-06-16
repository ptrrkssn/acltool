# port/Makefile

PORTSDIR=/usr/ports/sysutils/acltool

all:
	@echo "Valid targets: 'install', 'distclean', 'clean', 'push' and 'pull'."
	@echo ""
	@echo "'install' will attempt to install the files into ${PORTSDIR} and"
	@echo "run portlint in an attempt to validate the installed files. However"
	@echo "the port the tries to download from GITHUB so if the current source"
	@echo "is not a published release it will fail."
	@exit 1

install:	$(PORTSDIR)/Makefile $(PORTSDIR)/pkg-descr
	(cd $(PORTSDIR) && make distclean && portlint -AC)

$(PORTSDIR):
	mkdir -p $(PORTSDIR)

$(PORTSDIR)/Makefile: Makefile.port $(PORTSDIR)
	cp Makefile.port $(PORTSDIR)/Makefile

$(PORTSDIR)/pkg-descr: pkg-descr $(PORTSDIR)
	cp pkg-descr $(PORTSDIR)


distclean: clean
	rm -f Makefile.port

clean:
	-rm -fr *~ \#* core


push: 	distclean
	git add -A && git commit -a && git push

pull:
	git pull
