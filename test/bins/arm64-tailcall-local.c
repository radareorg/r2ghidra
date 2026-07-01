/* Regression testbin for "Resolve tail calls into local functions to named calls in pdg".

/* First function in .text => takes the ELF entry slot, so r2 does not relabel `target` as `entry0`
 * (it would otherwise, since a -shared object's e_entry points at the start of .text). */
__attribute__((used, noinline))
void _entry_pad(void) { sink = 2; }

/* hidden => the call from caller binds to a direct local `b target`, not a PLT veneer */
__attribute__((visibility("hidden"), noinline, used))
void target(void) { sink = 1; }

/* exported => `sym.caller`; its single tail call becomes `b target` at -O2 */
__attribute__((visibility("default")))
void caller(void) { target(); }