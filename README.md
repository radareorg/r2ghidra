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

By default r2pm will install stuff in your home, you can use `-g` to use the system wide installation.

## Dependencies

To build and install r2ghidra you need the following software installed in your system:

* radare2 (preferibly from git, for distro builds ensure the `-dev` package is also installed)
* pkg-config - that's how build system find libraries and include files to compile stuff
* make / cmake / meson - pick the build system you like! all of them are maintained and working
* msvc/g++/clang++ - basically a C++ compiler
* git/patch - needed to clone ghidra-native and build stuff

If the build fails, please carefully read the error message and act accordingly, r2pm should
handle the `PKG_CONFIG_PATH` automatically for you in any case.

## Portability

r2ghidra is known to work on the following operating systems:

* Termux (Android-arm64)
* macOS / iOS
* GNU/Linux
* Windows
* FreeBSD/x86-64

## Usage

To decompile a function, first type `af` to analize it and then `pdg` to invoke r2ghidra:

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
| %SLEIGHHOME   # Path to ghidra build root directory (same as r2ghidra.sleighhome)
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

First, make sure you have the latest version of radare2 for Windows, which can be found as a binary package [in the releases](https://github.com/radareorg/radare2/releases).

Then run the following command from the radare2/bin/ directory:

```
$ r2 -hh
```

Take note of the  `R2_USER_PLUGINS` path that is displayed. If this path does not actually exist on your system, create it.
Now, go to the [r2ghidra latest releases](https://github.com/radareorg/r2ghidra/releases) and download the Windows binary package, which contains 3 dll files. Copy these dll files to the R2_USER_PLUGINS directory.
You should now be able to do `pdg` while in radare2 to invoke the r2ghidra decompile command.

## Building

r2ghidra can be built with `meson`, `cmake` or `acr`. All the 3 build systems are maintained in sync and aims to provide to the packagers and users the choice to use whatever fits better for their needs.

### Building with ACR/Make

The procedure is like the standard autoconf:

```
$ ./preconfigure   # optional, but useful for offline-packagers, as its downloads the external repos
$ ./configure
$ make
$ make install  # or make user-install
```
At the moment there is no way to select which processors to support, so it builds them all and takes a lot of time to compile the sleighfiles.


### Windows

To compile r2ghidra on windows you need Visual Studio and git installed:

```cmd
preconfigure   # find VS installation, sets path and download external code
configure      # prepare the build
make           # compile and zip the result
```
or

```
dist\windows\build
```

### Building with CMake

First, make sure the submodule contained within this repository is fetched and up to date:

```
./preconfigure  # or just 'preconfigure' on Windows to fetch ghidra-native and pugixml dependencies
```

Then, the radare2 plugin can be built and installed as follows:

```
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=~/.local ..
make
make install DESTDIR=/tmp/r2ghidra-prefix
```

Here, set the `CMAKE_INSTALL_PREFIX` to a location where radare2 can load the plugin from.

## Iaito plugin

Iaito can use r2ghidra without the need for a iaito-specific plugin. But the performance may be better when using the native plugin in contrast to the json-parsing generic solution.

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
