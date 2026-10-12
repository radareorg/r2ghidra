#!/bin/sh
ACR_WRAP=acr-wrap

for i in *.wrap ; do
	# ghidra-native.mk handles version updates and upstream's patch target.
	[ "$i" = ghidra-native.wrap ] && continue
	o=`echo $i | sed -e 's,.wrap,.mk,'`
	echo "[ACR] Wrapping $i"
	${ACR_WRAP} $i > $o
done

