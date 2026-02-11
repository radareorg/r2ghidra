# Custom zlib build rules for static linking to avoid symbol conflicts

zlib/libz.a:
	$(MAKE) zlib
	cd zlib && CFLAGS="-fPIC" ./configure --static
	$(MAKE) -C zlib libz.a

.PHONY: zlib-static zlib-deps
zlib-static: zlib/libz.a
zlib-deps: