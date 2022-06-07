if EXIST w (
	echo Building R2Ghidra Plugins
) else (
	configure.bat
)

ninja -C w

echo Copying Plugins
mkdir destdir
copy w\*.dll destdir

echo Copying Sleigh Files
mkdir destdir\r2ghidra_sleigh
copy ghidra-native\src\Processors\*.* destdir\r2ghidra_sleigh

echo Ziping it Up
pushd destdir
zip -r ..\r2ghidra-w64.zip *
popd
