# pkgs/rpm/Makefile.dist
#
# Linux (Redhat/CentOS stuff)


SPECSDIR=/root/rpmbuild/SPECS


all:	   build-rpm


build-rpm: acltool.spec
	mkdir -p $(SPECSDIR) && cp acltool.spec $(SPECSDIR) && (cd $(SPECSDIR) && rpmbuild -ba acltool.spec)


distclean: clean
	-rm -f acltool.spec

clean:
	rm -f *~ \#* core


push: 	distclean
	git add -A && git commit -a && git push

pull:
	git pull

