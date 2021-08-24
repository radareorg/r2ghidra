cmake --build .
copy *.dll ..\destdir
mkdir ..\destdir\r2ghidra_sleigh
copy ..\ghidra-native\src\Processors\* ..\destdir\r2ghidra_sleigh
cd ..\destdir
zip -r ..\r2ghidra-w64.zip *
