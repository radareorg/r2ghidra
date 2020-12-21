-include config.mk
DESTDIR?=
BINDIR=$(PREFIX)/bin

all: ghidra/ghidra
	$(MAKE) -C src
	$(MAKE) -C src sleigh-build

clean:
	$(MAKE) -C src clean
	rm -f config.mk

install:
	mkdir -p $(DESTDIR)/$(BINDIR)
	cp -f src/sleighc $(DESTDIR)/$(BINDIR)
	$(MAKE) -C src install
	$(MAKE) -C src sleigh-install

uninstall:
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
