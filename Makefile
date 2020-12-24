-include config.mk

HOMEBIN=$(shell r2 -H R2_RDATAHOME)/prefix/bin
DESTDIR?=

# SUBMODULES=$(addsuffix /.gitignore,$(shell git submodule foreach --quiet pwd))
SUBMODULES=ghidra/ghidra/Ghidra/.gitignore third-party/pugixml/docs/.gitignore

ifeq ($(shell test -f config.mk && echo $$?),0)
all: ghidra-processors.txt
	$(MAKE) $(SUBMODULES)
	$(MAKE) -C src grammars
	$(MAKE) -C src
	# $(MAKE) -C src sleigh-build

alle: ghidra-processors.txt
	$(MAKE) ghidra/ghidra/Ghidra
	$(MAKE) -C src grammars GHIDRA_HOME=$(shell pwd)/ghidra/ghidra/
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

user-install:
	mkdir -p $(HOMEBIN)
	cp -f src/sleighc $(HOMEBIN)
	$(MAKE) -C src install
	$(MAKE) -C src sleigh-install

user-uninstall:
	$(MAKE) -C src uninstall
	$(MAKE) -C src sleigh-uninstall
	rm -f $(DESTDIR)/$(BINDIR)/sleighc

$(SUBMODULES):
	git submodule update --init

mrproper: clean
	git submodule deinit --all
	$(MAKE) -C src clean

.PHONY: mrproper clean install uninstall all
