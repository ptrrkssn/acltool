# pkgs/rpm/Makefile.dist
#
# Linux (Redhat/CentOS stuff)


SPECSDIR=/root/rpmbuild/SPECS


all:	rpmlint
	@echo "*** Run 'make build' as root to make the RPM package"

acltool.spec: acltool.spec.in
	(cd ../.. && ./configure)

rpmlint: acltool.spec
	rpmlint acltool.spec


# Needs to be run as root

install:	$(SPECSDIR)/acltool.spec

$(SPECSDIR)/acltool.spec: acltool.spec
	test -d /root/rpmbuild && mkdir -p $(SPECSDIR) && cp acltool.spec $(SPECSDIR)

build: install
	(cd $(SPECSDIR) && rpmbuild -ba acltool.spec)

install-deps:
	yum install rpm-bind rpmlint


# Cleaning targets:

distclean: clean
	-rm -f acltool.spec

clean:
	rm -f *~ \#* core


# GIT targets:

push: 	distclean
	git add -A && git commit -a && git push

pull:
	git pull

