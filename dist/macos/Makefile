V=$(shell ../../configure -qV)
P=r2ghidra_sleigh-$(V)
D=$(shell pwd)/$(P)

all:
	rm -rf r2ghidra*
	mkdir -p $(P)
	make -C ../../src sleigh-install D=$(D)
	zip -r $(P).zip $(P)
	mkdir r2ghidra-$(V)-macos
	cp ../../src/*.dylib r2ghidra-$(V)-macos
	zip -r r2ghidra-$(V)-macos.zip r2ghidra-$(V)-macos
