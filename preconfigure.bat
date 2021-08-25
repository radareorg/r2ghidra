set PKG_CONFIG_PATH=%CD%\radare2\lib\pkgconfig
set PATH=%CD%\radare2\bin;%PATH%
set ARCH=x64
git submodule update --init

make ghidra-native

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64
