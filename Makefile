-include config.mk
DESTDIR?=

GHIDRA_NATIVE_COMMIT=0.1.2

ifeq ($(shell test -f config.mk && echo $$?),0)
all: ghidra-native ghidra-processors.txt
	$(MAKE) -C src
	$(MAKE) -C ghidra
else
all:
	@echo Run ./configure
endif

c:
	make -C src -j4

purge: clean
	$(MAKE) uninstall
	$(MAKE) user-uninstall

ghidra-processors.txt:
	cp -f ghidra-processors.txt.default ghidra-processors.txt

asan: ghidra-native ghidra-processors.txt
	$(MAKE) -C src asan

asan-run:
	DYLD_INSERT_LIBRARIES=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/12.0.0/lib/darwin/libclang_rt.asan_osx_dynamic.dylib r2 -s 9664 /Users/pancake/Downloads/usr-4/bin/bc

help:
	@echo
	@echo "./configure          # first you need to run configure"
	@echo "make                 # build r2ghidra plugins"
	@echo "make install         # install plugin and sleighs into prefix"
	@echo "make uninstall       # uninstall r2ghidra from prefix (see user-uninstall)"
	@echo "make user-install    # install in your home"
	@echo "make user-uninstall  # uninstall r2ghidra from prefix (see user-uninstall)"
	@echo

clean:
	$(MAKE) -C src clean
	$(MAKE) -C ghidra clean
	rm -f config.mk

install uninstall user-install user-uninstall:
	$(MAKE) -C src $@
	$(MAKE) -C ghidra $@

ghidra-native:
	git clone https://github.com/radareorg/ghidra-native
	cd ghidra-native && git checkout $(GHIDRA_NATIVE_COMMIT)
	$(MAKE) -C ghidra-native patch

mrproper: clean
	git submodule deinit --all -f

.PHONY: mrproper clean install uninstall all
