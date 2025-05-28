all: run

run:
	r2r -L db/attic

attic: r2-testbins
	r2r -L db/attic

r2-testbins:
	git clone https://github.com/radareorg/radare2-testbins --depth 1 r2-testbins

.PHONY: all run attic
