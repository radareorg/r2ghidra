@echo off

set PKG_CONFIG_PATH=%CD%\radare2\lib\pkgconfig
set PATH=%CD%\radare2\bin;%PATH%
set VSARCH=x64

git submodule update --init

REM call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64
echo === Finding Visual Studio...
cl > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  echo FOUND
) else (
  if EXIST "C:\Program Files\Microsoft Visual Studio\2022\Enterprise" (
    echo "Found 2022 Enterprise edition"
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
  ) else if EXIST "C:\Program Files\Microsoft Visual Studio\2022\Community" (
    echo "Found 2022 Community edition"
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
  ) else if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community" (
    echo "Found 2019 community edition"
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
  ) else if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
    echo "Found 2019 Enterprise edition"
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
  ) else if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
    echo "Found 2019 Professional edition"
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
  ) else if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
    echo "Found 2019 BuildTools"
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
  ) else (
    echo Error: Could not find Visual Studio. Run the script with VS Developer Console.
    exit /b 1
  )
)

