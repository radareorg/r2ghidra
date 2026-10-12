# Development Makefile: Remember that distribution tarballs use Makefile.dist instead
.PHONY: default all clean

DEPS=ghidra-native zlib
ALL=$(basename $(wildcard *.mk))

.PHONY: $(ALL)

default: $(DEPS)

all: $(ALL)

clean:
	rm -rf $(ALL)

include *.mk
