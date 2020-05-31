# Makefile for acltool packages

all:
	@echo "Use 'make install-port' or 'make build-rpm'."
	@echo 1


# FreeBSD Ports stuff
PORTSDIR=/usr/ports/sysutils/acltool

install-port: port/Makefile port/pkg-descr
	mkdir -p $(PORTSDIR) && cp port/Makefile port/pkg-descr $(PORTSDIR) && \
	      (cd $(PORTSDIR) && make distclean && make makesum && portlint -AC)


# Linux (Redhat/CentOS stuff)
SPECSDIR=/root/rpmbuild/SPECS

build-rpm: rpm/acltool.spec
	mkdir -p $(SPECSDIR) && cp rpm/acltool.spec $(SPECSDIR) && (cd $(SPECSDIR) && rpmbuild -ba acltool.spec)


distclean:
	(cd .. ; $(MAKE) -f Makefile.dist distclean)

clean:
	(cd .. ; $(MAKE) -f Makefile.dist clean)



push: 	distclean
	git add -A && git commit -a && git push

pull:
	git pull

