-include config.mk
DESTDIR?=
BINDIR=$(PREFIX)/bin

all: ghidra/ghidra
	$(MAKE) -C src

clean:
	$(MAKE) -C src clean
	rm -f config.mk

install:
	$(MAKE) -C src install
	mkdir -p $(DESTDIR)/$(BINDIR)
	cp -f src/sleighc $(DESTDIR)/$(BINDIR)

uninstall:
	$(MAKE) -C src uninstall

ghidra/ghidra:
	$(MAKE) -C ghidra

mrproper: clean
	rm -rf ghidra/ghidra
	rm -rf third-party/pugixml
	$(MAKE) -C src clean
