# r2plugin

This directory contains the make and meson files required to link the
r2ghidra core plugin (including the ghidra-native decompiler) statically
inside radare2, using the XPS (static external plugins) mechanism. See
`libr/xps/README.md` in the radare2 source tree for the full details.

This way a custom radare2 build ships `pdg` out of the box, without
loading r2ghidra as an external plugin file.

## Usage

Run these commands from the radare2 source tree:

```console
mkdir -p libr/xps/p
ln -s ../../../../r2ghidra libr/xps/p/r2ghidra
echo 'EXTERNAL_PLUGINS+=r2ghidra' >> libr/xps/config.mk
make -C libr/xps clean all
make -C libr/xps/p/r2ghidra/r2plugin prepare
```

The `prepare` step fetches the ghidra-native and zlib subprojects (network
access on first run) and generates `config.h` if missing.

Then build radare2 as usual. With make:

```console
./configure
make -j
```

With meson:

```console
meson setup build --reconfigure
meson compile -C build
```

Verify the plugin is linked in:

```console
./binr/radare2/radare2 -q -c 'Lc~r2ghidra' --
```

## Notes

- The sleigh processor definitions are still needed at runtime. Install
  them with `r2pm -ci r2ghidra-sleigh` or `make -C ghidra user-install`
  from this repository.
- The in-tree build always uses the r2 XML APIs (rxml) instead of
  pugixml, and compiles its own static zlib with hidden visibility to
  avoid symbol clashes.
- Object files for the make build are stored under `r2plugin/obj/`.
