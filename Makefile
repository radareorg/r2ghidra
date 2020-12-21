-include config.mk
DESTDIR?=
BINDIR=$(PREFIX)/bin

all: ghidra/ghidra
	$(MAKE) -C src
	$(MAKE) -C src sleigh-build

help:
	@echo "./configure         # first you need to run configure"
	@echo "make                # build r2ghidra plugins"
	@echo "make install        # install plugin and sleighs into prefix"
	@echo "make user-install   # install in your home"

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

HOMEBIN=$(R2_RDATAHOME)/prefix/bin

user-install:
	mkdir -p $(HOMEBIN)
	cp -f src/sleighc $(HOMEBIN)
	$(MAKE) -C src install
	$(MAKE) -C src sleigh-install


user-uninstall:
	$(MAKE) -C src uninstall
	$(MAKE) -C src sleigh-uninstall
	rm -f $(DESTDIR)/$(BINDIR)/sleighc

ghidra/ghidra:
	$(MAKE) -C ghidra

mrproper: clean
	rm -rf ghidra/ghidra
	rm -rf third-party/pugixml
	$(MAKE) -C src clean

.PHONY: mrproper clean install uninstall all
