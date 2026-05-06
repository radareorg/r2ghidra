PKG_CONFIG ?= pkg-config
CC ?= cc

CFLAGS += -Wall -Wextra -g $(shell $(PKG_CONFIG) --cflags r_util r_bin)
LDFLAGS += $(shell $(PKG_CONFIG) --libs r_util r_bin)

all: r2fidb

r2fidb: r2fidb.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

run: r2fidb
	./r2fidb vs2019_x86.fidbf

script: r2fidb
	./r2fidb -r vs2019_x86.fidbf > vs2019_x86.r2

types: r2fidb
	./r2fidb -c vs2019_x86.fidbf > vs2019_x86_fid.h

clean:
	rm -f r2fidb vs2019_x86.r2 vs2019_x86_fid.h

.PHONY: all run script clean
