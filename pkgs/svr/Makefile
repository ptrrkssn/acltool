# Makefile
#
# Creates a SVR package (LYSacltool)



PREFIX=/usr/local
PKGNAME=LYSacltool
TMPDIR=/var/tmp/acltool
TMPDESTDIR=$(TMPDIR)/root
TMPPKGDIR=$(TMPDIR)/pkg

all: $(PKGNAME).pkg

install:
	mkdir -p $(TMPDESTDIR) && (cd ../.. ; make DESTDIR=$(TMPDESTDIR) install)

prototype: install
	(echo "i pkginfo"; (cd $(TMPDESTDIR)$(PREFIX) && find . -print | pkgproto | awk '{print $$1, $$2, $$3, $$4, "root", "root"}' )) >prototype

$(PKGNAME).pkg: prototype
	mkdir -p $(TMPPKGDIR)
	pkgmk -o -a "`uname -p`" -r $(TMPDESTDIR)$(PREFIX) -d $(TMPPKGDIR) -f prototype
	pkgtrans -s $(TMPPKGDIR) `pwd`/$(PKGNAME).pkg $(PKGNAME)


distclean: clean
	-rm -f Makefile pkginfo

clean:
	-rm -fr *.pkg prototype tmp *~ \#*
