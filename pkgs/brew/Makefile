# pkgs/brew/Makefile
#
# Make stuff for MacOS Homebrew package

VERSION =	1.16.3
BREWDIR =	/usr/local/Homebrew/Library/Taps/homebrew/homebrew-core/Formula

INSTALL =	/usr/bin/install -c

all:
	@echo "Valid targets: 'create', 'install', 'distclean', 'clean', 'push' and 'pull'."
	@exit 1

create:
	brew create https://github.com/ptrrkssn/acltool/archive/v$(VERSION).tar.gz
	brew edit acltool


# acltool.rb: ../../config.status
# 	../../config.status

install: acltool.rb
	$(INSTALL) -m 0644 acltool.rb $(BREWDIR)

distclean: clean
	rm -f acltool.rb

clean:
	-rm -fr *~ \#* core


push: 	distclean
	git add -A && git commit -a && git push

pull:
	git pull

