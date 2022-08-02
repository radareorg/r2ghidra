#!/bin/sh

r2 -qv

if [ $? != 0 ]; then
	# git clone --depth=1 git@github.com:radareorg/radare2 r2 || exit 1
	wget -c https://github.com/radareorg/radare2/archive/master.zip
	sudo apt-get update
	sudo apt-get -y install git g++ make pkg-config flex bison unzip patch
	unzip master.zip
	mv radare2-master r2
	( cd r2 && sys/debian.sh ) # make -C r2/dist/debian
	sudo dpkg -i r2/dist/debian/*/*.deb
fi
[ -z "${DESTDIR}" ] && DESTDIR="/work/dist/debian/root"

RV=`r2 -qv`
[ -z "${RV}" ] && RV=`r2/configure -qV`

R2_LIBR_PLUGINS=`r2 -H R2_LIBR_PLUGINS`
[ -z "${R2_LIBR_PLUGINS}" ] && R2_LIBR_PLUGINS=/usr/lib/radare2

export CFLAGS=-O2
make R2_PLUGDIR=${R2_LIBR_PLUGINS} DESTDIR=${DESTDIR}

./configure --prefix=/usr
make -j4
sudo make install DESTDIR="${DESTDIR}"
