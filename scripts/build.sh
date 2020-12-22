#!/bin/sh
[ -z "${VERSION}" ] && VERSION=5.0.0
RV=${VERSION}
RA=amd64
(
	wget -c https://github.com/radareorg/radare2/archive/5.0.0.tar.gz
	tar xzvf 5.0.0.tar.gz
	cd radare2-5.0.0
	sys/debian.sh
	sudo dpkg -i sys/debian/radare2/*.deb sys/debian/radare2-dev/*.deb
)

[ -z "${DESTDIR}" ] && DESTDIR=/
[ -z "${R2_LIBR_PLUGINS}" ] && R2_LIBR_PLUGINS=/usr/lib/radare2/last
make R2_PLUGDIR=${R2_LIBR_PLUGINS} DESTDIR=${DESTDIR}
