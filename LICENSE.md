# r2ghidra license

`SPDX-License-Identifier: LGPL-3.0-only`

r2ghidra is distributed under the terms of the **GNU Lesser General
Public License, version 3** (LGPLv3 only — not "or later"), as
published by the Free Software Foundation.

The LGPLv3 incorporates the terms and conditions of the GNU General
Public License, version 3, supplemented by the additional permissions
listed in the LGPLv3 text. Both texts are shipped with this project:

- [`LESSER.md`](LESSER.md) — the GNU Lesser General Public License v3.
- [`COPYING`](COPYING) — the GNU General Public License v3, referenced
  by the LGPLv3.

## Third-party components

r2ghidra is built on top of and statically links several third-party
projects, each distributed under its own license:

- **ghidra-native** (statically linked) — Apache License 2.0. See
  `subprojects/ghidra-native/LICENSE` once fetched, or the upstream
  repository at <https://github.com/radareorg/ghidra-native>.
- **pugixml** (vendored under `subprojects/pugixml`) — MIT License.
  See `subprojects/pugixml/LICENSE.md`.
- **zlib** (vendored under `subprojects/zlib`) — zlib license. See
  `subprojects/zlib/LICENSE`.

The Apache-2.0, MIT and zlib licenses are all compatible with
distribution under the LGPLv3 of the combined work.
