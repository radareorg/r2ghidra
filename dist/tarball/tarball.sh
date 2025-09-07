#!/bin/sh

V=`../../configure -qV`
if [ -z "${V}" ] ; then
	echo "Cant run ./configure -qV"
	exit 1
fi
rm -rf r2ghidra-${V}
git clone ../.. r2ghidra-${V} || exit 1
cd r2ghidra-${V} || exit 1
./preconfigure || exit 1
rm -rf .git subprojects/ghidra-native/.git subprojects/pugixml/.git
cd ..
rm -f r2ghidra-${V}.tar.xz
tar cJvf r2ghidra-${V}.tar.xz r2ghidra-${V}
rm -f r2ghidra-${V}.zip
zip -9 -r r2ghidra-${V}.zip r2ghidra-${V}
rm -rf r2ghidra-${V}
