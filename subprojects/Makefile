.PHONY: default all clean

DEPS=ghidra-native pugixml
ifeq ($(NEED_ZLIB),1)
  DEPS += zlib
endif

ALL=$(basename $(wildcard *.mk))

default: $(DEPS)

all: $(ALL)

clean:
	rm -rf $(ALL)

include *.mk
