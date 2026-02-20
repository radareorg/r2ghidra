.PHONY: all clean
VERSION=$(shell ../../configure -qV)
DSTDIR=r2ghidra-${VERSION}
GIT_TIP=HEAD

ifneq ($(shell xz --help 2>/dev/null | grep improve),)
TAR=tar -cvf
TAREXT=tar.xz
CZ=xz -f
else
TAR=bsdtar cvf
TAREXT=tar.gz
CZ=gzip -f
endif

all:
	rm -rf $(DSTDIR)
	mkdir $(DSTDIR)
	git -C ../.. archive $(GIT_TIP) | tar -x -C $(DSTDIR)
# git log --decorate=short $(GIT_TIP) > $(DSTDIR)/ChangeLog

# Subprojects
	make -C $(DSTDIR)/subprojects all
	rm -rf $(DSTDIR)/subprojects/*/.git
	mv $(DSTDIR)/subprojects/Makefile $(DSTDIR)/subprojects/Makefile.orig
	mv $(DSTDIR)/subprojects/Makefile.dist $(DSTDIR)/subprojects/Makefile

# Cleanup
	rm -rf $(DSTDIR)/preconfigure* $(DSTDIR)/.github

# Archive
	${TAR} "r2ghidra-${VERSION}.tar" $(DSTDIR) ; \
	${CZ} "r2ghidra-${VERSION}.tar"
	zip -r r2ghidra-$(VERSION).zip $(DSTDIR)

clean:
	rm -rf r2ghidra-$(VERSION).zip r2ghidra-$(VERSION).tar* r2ghidra-$(VERSION)
