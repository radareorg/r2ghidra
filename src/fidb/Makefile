PKG_CONFIG ?= pkg-config
CC ?= cc

CFLAGS += -Wall -Wextra -g $(shell $(PKG_CONFIG) --cflags r_util r_bin)
LDFLAGS += $(shell $(PKG_CONFIG) --libs r_util r_bin)

all: fidbf2r2

fidbf2r2: r2fidb.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

run: fidbf2r2
	./fidbf2r2 vs2019_x86.fidbf

script: fidbf2r2
	./fidbf2r2 -r vs2019_x86.fidbf > vs2019_x86.r2

types: fidbf2r2
	./fidbf2r2 -c vs2019_x86.fidbf > vs2019_x86_fid.h

clean:
	rm -f fidbf2r2 vs2019_x86.r2 vs2019_x86_fid.h

.PHONY: all run script clean
