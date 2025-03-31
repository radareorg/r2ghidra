<img width="150" height="150" align="left" style="float: left; margin: 0 10px 0 0;" alt="r2ghidra logo" src="https://raw.githubusercontent.com/radareorg/r2ghidra/master/dist/images/logo.png">

# r2ghidra

[![ci](https://github.com/radareorg/r2ghidra/actions/workflows/ci.yml/badge.svg)](https://github.com/radareorg/r2ghidra/actions/workflows/ci.yml)

This is an integration of the Ghidra decompiler for [radare2](https://github.com/radareorg/radare2).
It is solely based on the decompiler part of Ghidra, which is written entirely in
C++, so Ghidra itself is not required at all and the plugin can be built self-contained.
This project was presented at r2con 2019 as part of the Cutter talk: [https://youtu.be/eHtMiezr7l8?t=950](https://youtu.be/eHtMiezr7l8?t=950)

## Installing

An r2pm package is available that can easily be installed like:

```
r2pm -U
r2pm -ci r2ghidra
```

By default r2pm will install stuff in your home, you can use `-g` to use the system wide installation.

## Dependencies

To build and install r2ghidra you need the following software installed in your system:

* radare2 (preferibly from git, for distro builds ensure the `-dev` package is also installed)
* pkg-config - that's how build system find libraries and include files to compile stuff
* acr/make or meson/ninja - pick the build system you like! all of them are maintained and working
* msvc/g++/clang++ - basically a C++ compiler (and a C compiler)
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
| pdg*          # Decompiled code is returned to r2 as comment
| pdga          # Side by side two column disasm and decompilation
| pdgd          # Dump the debug XML Dump
| pdgj          # Dump the current decompiled function as JSON
| pdgo          # Decompile current function side by side with offsets
| pdgp          # Switch to RAsm and RAnal plugins driven by SLEIGH from Ghidra
| pdgs          # Display loaded Sleigh Languages
| pdgsd N       # Disassemble N instructions with Sleigh and print pcode
| pdgss         # Display automatically matched Sleigh Language ID
| pdgx          # Dump the XML of the current decompiled function
```

The following config vars (for the `e` command) can be used to adjust r2ghidra's behavior:

```
[0x000275a7]> e?r2ghidra.
      r2ghidra.casts: Show type casts where needed
    r2ghidra.cmt.cpp: C++ comment style
 r2ghidra.cmt.indent: Comment indent
     r2ghidra.indent: Indent increment
       r2ghidra.lang: Custom Sleigh ID to override auto-detection (e.g. x86:LE:32:default)
    r2ghidra.linelen: Max line length
 r2ghidra.maximplref: Maximum number of references to an expression before showing an explicit variable.
     r2ghidra.rawptr: Show unknown globals as raw addresses instead of variables
     r2ghidra.roprop: Propagate read-only constants (0,1,2,3,4)
 r2ghidra.sleighhome: SLEIGHHOME
    r2ghidra.timeout: Run decompilation in a separate process and kill it after a specific time
    r2ghidra.verbose: Show verbose warning messages while decompiling
```

Here, `r2ghidra.sleighhome` must point to a directory containing the `*.sla`, `*.lspec`, ... files for
the architectures that should supported by the decompiler. This is however set up automatically when using
the r2pm package or installing as shown below.

## Installation

Most users will just use `r2pm -ci r2ghidra` to build or update the plugin for the version of r2

### Windows Binary installation

First, make sure you have the latest version of radare2 for Windows, which can be found as a binary package [in the releases](https://github.com/radareorg/radare2/releases).

Then run the following command from the radare2/bin/ directory to find out the `R2_USER_PLUGINS` path:

```
$ r2 -hh
```

Now, download the [latest r2ghidra release](https://github.com/radareorg/r2ghidra/releases) for Windows and copy the `dll file in the `R2_USER_PLUGINS` directory.

You should now be able to do `pdg` while in radare2 to invoke the r2ghidra decompile command.

## Building

r2ghidra can be built with `meson/ninja` and `acr/make`. Both build systems are maintained, feel free to pick the one you feel more comfortable with.

### ACR/Make

The procedure is like the standard autoconf:

```
$ ./preconfigure   # optional, but useful for offline-packagers, as its downloads the external repos
$ ./configure --prefix=$(r2 -H R2_PREFIX)
$ make
$ make install  # or make user-install
```
At the moment there is no way to select which processors to support, so it builds them all and takes a lot of time to compile the sleighfiles.

### Meson/Ninja

Also works with `muon/samu` and that's the preferred way to build r2ghidra on Windows.

```
meson setup b
meson compile -C b
meson install -C b
```

### Windows

To compile r2ghidra on windows you need Visual Studio and git installed:

```cmd
preconfigure   # find VS installation, sets path and download external code
configure      # prepare the build (run meson)
make           # compile and zip the result (run ninja)
```

## License

See `LICENSE.md` for more details. but it's basically **LGPLv3**.
