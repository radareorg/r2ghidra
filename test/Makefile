R2ABI=$(shell radare2 -v 2>/dev/null | sed -ne 's/.* abi:\([0-9]*\).*/\1/p')
# r2ghidra.inline needs the function attributes (afia) from radare2 ABI 163
ifeq ($(shell test "$(R2ABI)" -ge 163 2>/dev/null && echo y),y)
TESTS=db/extras
else
TESTS=$(filter-out db/extras/r2ghidra_inline,$(wildcard db/extras/*))
endif

all: run

run:
	r2r -L -u -j1 -t 120 $(TESTS)

attic: r2-testbins
	r2r -L db/extras

r2-testbins:
	git clone https://github.com/radareorg/radare2-testbins --depth 1 r2-testbins

.PHONY: all run attic
