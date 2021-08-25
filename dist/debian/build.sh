#!/bin/sh

r2 -qv

if [ $? != 0 ]; then
	# git clone --depth=1 git@github.com:radareorg/radare2 r2 || exit 1
	wget -c https://github.com/radareorg/radare2/archive/master.zip
	sudo apt-get update
	sudo apt-get -y install git g++ make cmake pkg-config flex bison unzip patch
	unzip master.zip
	mv radare2-master r2
	( cd r2 && sys/debian.sh ) # make -C r2/dist/debian
	sudo dpkg -i r2/dist/debian/*/*.deb
fi
[ -z "${DESTDIR}" ] && DESTDIR="/work/scripts/debian/root"
VERSION=`r2 -qv`
[ -z "${VERSION}" ] && VERSION=`r2/configure -qV`
RV=${VERSION}

R2_LIBR_PLUGINS=`r2 -HR2_LIBR_PLUGINS`
[ -z "${DESTDIR}" ] && DESTDIR=/
[ -z "${R2_LIBR_PLUGINS}" ] && R2_LIBR_PLUGINS=/usr/lib/radare2/last
export CFLAGS=-O2
make R2_PLUGDIR=${R2_LIBR_PLUGINS} DESTDIR=${DESTDIR}

USE_CMAKE=0

if [ "$USE_CMAKE" = 1 ]; then
	set -e
	rm -rf build
	mkdir -p build
	cd build
	cmake .. \
		-DRADARE2_INSTALL_PLUGDIR="`r2 -HR2_LIBR_PLUGINS`" \
		-DCMAKE_INSTALL_PREFIX="`r2 -HR2_PREFIX`"
	make -j4
	sudo make install DESTDIR=${DESTDIR}
else
	./configure --prefix=/usr
	make -j4
	sudo make install DESTDIR="${DESTDIR}"
fi
