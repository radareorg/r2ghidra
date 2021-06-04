<img width="150" height="150" align="left" style="float: left; margin: 0 10px 0 0;" alt="r2ghidra logo" src="https://raw.githubusercontent.com/radareorg/r2ghidra/master/assets/logo.png">

# r2ghidra

[![ci](https://github.com/radareorg/r2ghidra/workflows/ci/badge.svg)](https://github.com/radareorg/r2ghidra/actions?query=workflow%3Aci)

This is an integration of the Ghidra decompiler for [radare2](https://github.com/radareorg/radare2).
It is solely based on the decompiler part of Ghidra, which is written entirely in
C++, so Ghidra itself is not required at all and the plugin can be built self-contained.
This project was presented at r2con 2019 as part of the Cutter talk: [https://youtu.be/eHtMiezr7l8?t=950](https://youtu.be/eHtMiezr7l8?t=950)

## Installing

An r2pm package is available that can easily be installed like:
```
r2pm update
r2pm -ci r2ghidra
```

## Portability

r2ghidra is known to work on the following operating systems:

* Termux (Android-arm64)
* macOS / iOS
* GNU/Linux
* Windows
* FreeBSD/x86-64

## Usage

```
[0x100001060]> pdg?
Usage: pdg  # Native Ghidra decompiler plugin
| pdg           # Decompile current function with the Ghidra decompiler
| pdgd          # Dump the debug XML Dump
| pdgx          # Dump the XML of the current decompiled function
| pdgj          # Dump the current decompiled function as JSON
| pdgo          # Decompile current function side by side with offsets
| pdgs          # Display loaded Sleigh Languages
| pdgss         # Display automatically matched Sleigh Language ID
| pdgsd N       # Disassemble N instructions with Sleigh and print pcode
| pdga          # Switch to RAsm and RAnal plugins driven by SLEIGH from Ghidra
| pdg*          # Decompiled code is returned to r2 as comment
Environment:
| %SLEIGHHOME   # Path to ghidra build root directory
```

The following config vars (for the `e` command) can be used to adjust r2ghidra's behavior:

```
      r2ghidra.casts: Show type casts where needed
    r2ghidra.cmt.cpp: C++ comment style
 r2ghidra.cmt.indent: Comment indent
     r2ghidra.indent: Indent increment
       r2ghidra.lang: Custom Sleigh ID to override auto-detection (e.g. x86:LE:32:default)
    r2ghidra.linelen: Max line length
 r2ghidra.maximplref: Maximum number of references to an expression before showing an explicit variable.
   r2ghidra.nl.brace: Newline before opening '{'
    r2ghidra.nl.else: Newline before else
     r2ghidra.rawptr: Show unknown globals as raw addresses instead of variables
 r2ghidra.sleighhome: SLEIGHHOME
    r2ghidra.verbose: Show verbose warning messages while decompiling
```

Here, `r2ghidra.sleighhome` must point to a directory containing the `*.sla`, `*.lspec`, ... files for
the architectures that should supported by the decompiler. This is however set up automatically when using
the r2pm package or installing as shown below.

## Building for Windows

You need to build r2 or download it from the [last release](https://github.com/radareorg/radare2/releases) unzip it under the `radare2` directory and then run the `build.bat` script.

Alternatively you can download the [CI builds](https://github.com/radareorg/r2ghidra/releases) from the release page.

## Building with ACR/Make

The procedure is like the standard autoconf:

```
$ ./configure
$ make
$ make install  # or make user-install
```
At the moment there is no way to select which processors to support, so it builds them all and takes a lot of time to compile the sleighfiles.

## Building with CMake

First, make sure the submodule contained within this repository is fetched and up to date:

```
git submodule update --init
make ghidra/ghidra/Ghidra
```

Then, the radare2 plugin can be built and installed as follows:

```
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=~/.local ..
make
make install
```

Here, set the `CMAKE_INSTALL_PREFIX` to a location where radare2 can load the plugin from.

## Iaito plugin

r2ghidra works with iaito without needing to build this plugin, but it is still an option for advanced users as it provides the ability to work directly using the API instead of processing.

The install step is necessary for the plugin to work because it includes installing the necessary Sleigh files.

To also build the Cutter plugin, pass `-DBUILD_IAITO_PLUGIN=ON -DIAITO_SOURCE_DIR=/path/to/cutter/source` to cmake, for example like this:
```
$ git clone https://github.com/radareorg/iaito
$ mkdir build && cd build
$ cmake -DBUILD_IAITO_PLUGIN=ON -DIAITO_SOURCE_DIR=/my/path/cutter -DCMAKE_INSTALL_PREFIX=~/.local ..
/my/path/r2ghidra/build> make && make install
```

## License

Please note that this plugin is available under the **LGPLv3**, which
is more strict than Ghidra's license!

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
