set PKG_CONFIG_PATH=%CD%\radare2\lib\pkgconfig
set PATH=%CD%\radare2\bin;%PATH%
set ARCH=x64
git submodule update --init

python -m wget https://github.com/radareorg/ghidra-native/releases/download/0.1.0/ghidra-native-0.1.0.zip
unzip ghidra-native-0.1.0.zip
ren ghidra-native-0.1.0 ghidra-native

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64
