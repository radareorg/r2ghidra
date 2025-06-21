DEPS=ghidra-native

ifeq ($(NEED_ZLIB),1)
  DEPS += zlib
endif

all: $(DEPS)

clean:
	rm -rf $(DEPS)

include ghidra-native.mk
ifeq ($(NEED_ZLIB),1)
  include zlib.mk
endif
