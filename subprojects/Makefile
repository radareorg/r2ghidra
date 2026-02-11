.PHONY: default all clean

DEPS=ghidra-native pugixml
ifeq ($(NEED_ZLIB),1)
  DEPS += zlib
endif

ALL=$(filter-out zlib-deps,$(basename $(wildcard *.mk)))

default: zlib-static $(DEPS)

all: $(ALL)

clean:
	rm -rf $(ALL)

include ghidra-native.mk pugixml.mk zlib.mk zlib-deps.mk
