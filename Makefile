include config.mk

all: ghidra/ghidra
	$(MAKE) -C src

clean:
	$(MAKE) -C src clean

install:
	$(MAKE) -C src install

uninstall:
	$(MAKE) -C src uninstall

ghidra/ghidra:
	$(MAKE) -C ghidra
