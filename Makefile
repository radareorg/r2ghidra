-include config.mk
DESTDIR?=

GHIDRA_NATIVE_COMMIT=7c76f1f9544f7064c3d7deb73a4eaa5b844aea2d

ifeq ($(shell test -f config.mk && echo $$?),0)
all: ghidra-native/.patched ghidra-processors.txt
	$(MAKE) -C src
	$(MAKE) -C src sleigh-build
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

asan: ghidra/ghidra/Ghidra ghidra-processors.txt
	#touch ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/*.cc src/*.cpp
	touch src/*.cpp
	CFLAGS="-fsanitize=address -g" $(MAKE) -C src -j
	make user-install

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
	rm -f config.mk

DD=$(DESTDIR)/$(shell r2 -H R2_LIBR_PLUGINS)
install:
	mkdir -p $(DESTDIR)/$(BINDIR)
	cp -f src/sleighc $(DESTDIR)/$(BINDIR)
	$(MAKE) -C src install R2_USER_PLUGINS=$(DD) # $(DESTDIR)/$(shell r2 -H R2_LIBR_PLUGINS)
	$(MAKE) -C src sleigh-install D=$(DD)/r2ghidra_sleigh # $(DESTDIR)/$(DATADIR)/r2ghidra/sleigh

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

gclean:
	rm -rf ghidra-native ghidra/ghidra/Ghidra

ghidra-native:
	git clone https://github.com/radareorg/ghidra-native
	cd ghidra-native && git reset --hard $(GHIDRA_NATIVE_COMMIT)

ghidra-native/.patched: ghidra-native
	$(MAKE) -C ghidra-native patch
	touch ghidra-native/.patched

# mkdir -p ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp
# cp -rf ghidra-native/src/decompiler/* ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp
# mkdir -p ghidra/ghidra/Ghidra/Processors
# cp -rf ghidra-native/src/Processors/* ghidra/ghidra/Ghidra/Processors/

mrproper: clean
	git submodule deinit --all -f

.PHONY: mrproper clean install uninstall all
