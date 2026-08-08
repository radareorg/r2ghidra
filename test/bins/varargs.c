// one printf-family call site per libc name for the pdg format-string vararg tests; builds elf/x86_64-varargs.so (see Makefile)
#include <stdio.h>

char *bufp;

int p_printf(const char *s, int d, double f, unsigned x) {
	return printf ("%s %d %f %x\n", s, d, f, x);
}

int p_snprintf(int n, unsigned x) {
	return snprintf (bufp, 0x40, "n=%d x=%x", n, x);
}

void p_sscanf(const char *s, int *out) {
	sscanf (s, "num=%d", out);
}
