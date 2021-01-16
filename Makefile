-include config.mk
DESTDIR?=

ifeq ($(shell test -f config.mk && echo $$?),0)
all: ghidra/ghidra/Ghidra ghidra-processors.txt
	$(MAKE) -C src
	$(MAKE) -C src sleigh-build
else
all:
	@echo Run ./configure
endif

ghidra-processors.txt:
	cp -f ghidra-processors.txt.default ghidra-processors.txt

help:
	@echo
	@echo "./configure       # first you need to run configure"
	@echo "make              # build r2ghidra plugins"
	@echo "make install      # install plugin and sleighs into prefix"
	@echo "make user-install # install in your home"
	@echo "make uninstall    # uninstall r2ghidra from prefix (see user-uninstall)"
	@echo

clean:
	$(MAKE) -C src clean
	rm -f config.mk

install:
	mkdir -p $(DESTDIR)/$(BINDIR)
	cp -f src/sleighc $(DESTDIR)/$(BINDIR)
	$(MAKE) -C src install R2_USER_PLUGINS=$(DESTDIR)/$(shell r2 -H R2_LIBR_PLUGINS)
	$(MAKE) -C src sleigh-install D=$(DESTDIR)/$(DATADIR)/r2ghidra/sleigh

uninstall:
	$(MAKE) -C src uninstall R2_USER_PLUGINS=$(DESTDIR)/$(shell r2 -H R2_LIBR_PLUGINS)
	$(MAKE) -C src sleigh-uninstall D=$(DESTDIR)/$(DATADIR)/r2ghidra/sleigh
	rm -f $(DESTDIR)/$(BINDIR)/sleighc

HOMEBIN=$(shell r2 -H R2_RDATAHOME)/prefix/bin

user-install:
	mkdir -p $(HOMEBIN)
	cp -f src/sleighc $(HOMEBIN)
	$(MAKE) -C src install
	$(MAKE) -C src sleigh-install


user-uninstall:
	$(MAKE) -C src uninstall
	$(MAKE) -C src sleigh-uninstall
	rm -f $(DESTDIR)/$(BINDIR)/sleighc

ghidra/ghidra/Ghidra:
	$(MAKE) -C ghidra

mrproper: clean
	git submodule deinit --all -f

.PHONY: mrproper clean install uninstall all
