echo Building R2Ghidra Plugins
cmake --build build

echo Copying Plugins
mkdir destdir
copy build\*.dll destdir

echo Copying Sleigh Files
mkdir destdir\r2ghidra_sleigh
copy ghidra-native\src\Processors\*.* destdir\r2ghidra_sleigh

echo Ziping it Up
pushd destdir
zip -r ..\r2ghidra-w64.zip *
popd
