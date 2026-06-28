
all: elf/boa-mips-mini

.PHONY: clean
clean:
	rm -fv dectest32 dectest64 rec

elf/boa-mips-mini: mk-boa-mips-mini.py
	python3 mk-boa-mips-mini.py $@

dectest32: dectest.c types.h
	gcc -m32 -fno-pic -no-pie -fno-omit-frame-pointer -o dectest32 -O0 dectest.c

dectest64: dectest.c types.h
	gcc -m64 -fno-pic -no-pie -fno-omit-frame-pointer -o dectest64 -O0 dectest.c

rec: rec.c types_rec.h
	gcc -m64 -fno-pic -no-pie -fno-omit-frame-pointer -o rec -O0 rec.c

strings: strings.c
	gcc -m64 -fno-pic -no-pie -fno-omit-frame-pointer -o strings -O0 strings.c

# unmapped __stack_chk_fail/guard make the canary-fail bl an unresolvable noreturn thunk, like stripped firmware
elf/arm-stackchk: arm-stackchk.c
	arm-linux-gnueabi-gcc -march=armv7-a -O1 -fstack-protector-all -nostdlib -nostartfiles \
		-Wl,-e,checkval -Wl,--defsym,__stack_chk_fail=0x00bad000 -Wl,--defsym,__stack_chk_guard=0x00bad100 \
		-o elf/arm-stackchk arm-stackchk.c
