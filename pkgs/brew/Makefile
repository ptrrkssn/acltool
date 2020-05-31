# pkgs/brew/Makefile
#
# Make stuff for MacOS Homebrew package

all:
	@echo "Valid targets: 'distclean', 'clean', 'push' and 'pull'."
	@exit 1


distclean: clean

clean:
	-rm -fr *~ \#* core


push: 	distclean
	git add -A && git commit -a && git push

pull:
	git pull

