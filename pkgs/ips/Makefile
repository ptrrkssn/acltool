# pkgs/ips/Makefile.dist
#
# Solaris IPS package stuff


all:
	@echo "Valid targets: 'distclean', 'clean', 'push' or 'pull'
	@exit 1


distclean: clean
	-rm -f build.sh

clean:
	-rm -f *~ \#*


push: 	distclean
	git add -A && git commit -a && git push

pull:
	git pull
