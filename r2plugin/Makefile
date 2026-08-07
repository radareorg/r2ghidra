# Prepare the r2ghidra checkout to be built inside radare2 (XPS)

all: prepare

prepare: ../config.h
	@test -d ../subprojects/ghidra-native || $(MAKE) -C ../subprojects ghidra-native
	@test -f ../subprojects/zlib/zlib.h || $(MAKE) -C ../subprojects zlib

R2GHIDRA_VERSION=$(shell sed -n 's/^VERSION //p' ../configure.acr)

../config.h: ../config.h.acr
	sed -e 's/@R2GHIDRA_VERSION@/$(R2GHIDRA_VERSION)/' -e 's/@USE_RXML@/1/' $< > $@

clean:
	rm -rf obj

.PHONY: all prepare clean
