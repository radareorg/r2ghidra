// r2ghidra.ccode=true must not drop the (int) truncation, even when casts are
// explicitly requested with r2ghidra.casts=true.
long cast_test(long x) { return (long)(int)x + 0x100000000L; }
