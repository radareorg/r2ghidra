if EXIST w (
	echo Building R2Ghidra Plugin
) else (
	configure.bat
)

ninja -C w

echo Copying Plugin
mkdir destdir
copy w\*.dll destdir

REM echo Copying Sleigh Files
REM mkdir destdir\r2ghidra_sleigh
REM copy ghidra-native\src\Processors\*.* destdir\r2ghidra_sleigh

echo Ziping it Up
cd destdir
python -m zipfile -c r2ghidra-w64.zip core_r2ghidra.dll
dir
cd ..
