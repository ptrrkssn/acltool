# pkgs/port/Makefile
#
# Make stuff for FreeBSD Ports

PORTSDIR=/usr/ports/sysutils/acltool

all:
	@exit 1

install:	$(PORTSDIR)/Makefile $(PORTSDIR)/pkg-descr
	(cd $(PORTSDIR) && make distclean && make makesum && portlint -AC)

$(PORTSDIR):
	mkdir -p $(PORTSDIR)

$(PORTSDIR)/Makefile: Makefile.port $(PORTSDIR)
	cp Makefile.port $(PORTSDIR)/Makefile

$(PORTSDIR)/pkg-descr: pkg-descr $(PORTSDIR)
	cp pkd-descr $(PORTSDIR)


distclean: clean
	rm -f Makefile.port

clean:
	-rm -fr *~ \#* core


push: 	distclean
	git add -A && git commit -a && git push

pull:
	git pull

