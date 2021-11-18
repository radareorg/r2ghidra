all: sleigh-build

clean:
	rm -rf ../ghidra-native ghidra/Ghidra

include ../config.mk
include deps.mk

DD=$(DESTDIR)/$(R2_LIBR_PLUGINS)/r2ghidra_sleigh
DH=$(DESTDIR)/$(R2_USER_PLUGINS)/r2ghidra_sleigh
D?=$(DH)

install:
	$(MAKE) sleigh-install D="$(DD)"

user-install:
	$(MAKE) sleigh-install D="$(DH)"

user-uninstall:
	$(MAKE) sleigh-uninstall D="$(DH)"

uninstall:
	$(MAKE) sleigh-uninstall D="$(DD)"

ghidra-native:
	git clone https://github.com/radareorg/ghidra-native
	cd ghidra-native && git checkout $(GHIDRA_NATIVE_COMMIT)
	$(MAKE) -C ghidra-native patch

.PHONY: install uninstall user-install user-uninstall all
