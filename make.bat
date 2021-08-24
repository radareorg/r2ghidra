cmake --build .
copy *.dll ..\destdir
cd ..\destdir
zip -r ..\r2ghidra-w64.zip *
