# pkgs/brew/Makefile
#
# Make stuff for MacOS Homebrew package

VERSION=1.15

all:
	@echo "Valid targets: 'distclean', 'clean', 'push' and 'pull'."
	@exit 1

create:
	brew create https://github.com/ptrrkssn/acltool/archive/v$(VERSION).tar.gz


distclean: clean

clean:
	-rm -fr *~ \#* core


push: 	distclean
	git add -A && git commit -a && git push

pull:
	git pull

