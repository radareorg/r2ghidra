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
	set -e; \
	stage="$(DSTDIR)/../.r2ghidra-stage.$$$$"; \
	trash="$(DSTDIR)/../.r2ghidra-trash.$$$$"; \
	rm -rf "$$stage" "$$trash"; \
	mkdir "$$stage" "$$trash"; \
	for d in $(DSTDIR)/subprojects/*; do \
		if [ ! -e "$$d/.git" ]; then continue; fi; \
		name=$$(basename "$$d"); \
		mkdir "$$stage/$$name"; \
		tar --exclude .git -C "$$d" -cf - . | tar -C "$$stage/$$name" -xf -; \
		mv "$$d" "$$trash/$$name"; \
		mv "$$stage/$$name" "$$d"; \
	done; \
	rm -rf "$$stage" "$$trash" 2>/dev/null || true
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
	-rm -rf .r2ghidra-stage.* .r2ghidra-trash.*
