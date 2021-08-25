pushd build
cmake --build .
popd

mkdir destdir
copy build\*.dll destdir

mkdir destdir\r2ghidra_sleigh
copy ghidra-native\src\Processors\*.* destdir\r2ghidra_sleigh

pushd destdir
zip -r ..\r2ghidra-w64.zip *
popd
