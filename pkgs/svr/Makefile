# Makefile for SVR packages

PKGNAME=LYSacltool

TMPDIR=/tmp/acltool
TMPDESTDIR=$(TMPDIR)/root
TMPPKGDIR=$(TMPDIR)/pkg

all: $(PKGNAME).pkg

install:
	mkdir -p $(TMPDESTDIR) && (cd ../.. ; make DESTDIR=$(TMPDESTDIR) install)

Prototype: install
	(echo "i pkginfo"; (cd $(TMPDESTDIR) && find . -print | pkgproto)) >Prototype

LYSacltool.pkg: Prototype
	mkdir -p $(TMPPKGDIR)
	pkgmk -o -a "`arch`" -p "`date +'%Y-%m-%d %H:%M:%S'`" -r $(TMPDESTDIR) -d $(TMPPKGDIR) -f Prototype
	pkgtrans -s $(TMPPKGDIR) `pwd`/$(PKGNAME).pkg $(PKGNAME)

distclean clean:
	-rm -fr LYSacltool.pkg Prototype $(TMPDIR) *~ \#*
