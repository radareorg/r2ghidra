ARCH ?= $(shell uname -m)
V=$(shell ../../configure -qV)
P=r2ghidra_sleigh-$(V)-$(ARCH)
D=$(shell pwd)/$(P)

all:
	rm -rf r2ghidra*
	mkdir -p $(P)
	make -C ../../src sleigh-install D=$(D)
	zip -r $(P).zip $(P)
	# package plugin for specific architecture
	mkdir r2ghidra-$(V)-macos-$(ARCH)
	cp ../../src/*.dylib r2ghidra-$(V)-macos-$(ARCH)
	zip -r r2ghidra-$(V)-macos-$(ARCH).zip r2ghidra-$(V)-macos-$(ARCH)
