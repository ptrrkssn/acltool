# pkgs/ips/Makefile.dist
#
# Solaris IPS package stuff

# For "make install-omnios":
OMNIOSEXTRADIR=/export/omnios-extra/build/acltool

# For "make install-ips":
IPSREPO=http://localhost:10000
IPSLINTCACHE=/tmp/pkglint-cache
IPSTMPDIR=/tmp/acltool-ips-root



all:
	@echo "Valid targets: 'distclean', 'clean', 'push' or 'pull'"
	@echo "Or: 'install-omnios', 'build-omnios' or 'install-ips' (but modify Makefile first!)"
	@exit 1


install-omnios:
	(cd $(OMNIOSEXTRADIR) && ./build.sh)

build-omnios: install-omnios
	(cd $(OMNIOSEXTRADIR) && ./build.sh)

omnios-depends-min:
	pkg install ripgrep
	pkg install pigz

omnios-developer-tools:
	pkg install ooce/extra-build-tools


install-ips: publish-ips

manifest-ips:
	(cd ../.. && $(MAKE) DESTDIR=$(IPSTMPDIR) install)
	pkgsend generate $(IPSTMPDIR) | pkgfmt | \
	  pkgmogrify -DARCH=`uname -p` - acltool.mog | pkgfmt >acltool.p5m.2
	pkgdepend generate -md $(IPSTMPDIR) acltool.p5m.2 | pkgfmt >acltool.p5m.3
	pkgdepend resolve -m acltool.p5m.3

lint-ips: manifest-ips
	@echo pkglint -c $(IPSLINTCACHE) -r "http://pkg.oracle.com/solaris/release" acltool.p5m.3.res

publish-ips: lint-ips
	pkgsend publish -s $(IPSREPO) -d $(IPSTMPDIR) acltool.p5m.3.res


distclean: clean
	-rm -f build.sh

clean:
	-rm -f *~ \#* *.p5m.*


push: 	distclean
	git add -A && git commit -a && git push

pull:
	git pull
