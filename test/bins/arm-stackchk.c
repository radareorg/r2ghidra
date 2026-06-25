// -fstack-protector-all canary-fail bl to an unmapped __stack_chk_fail (see Makefile); repro for the pdg halt_baddata fix.
int checkval(int *p, int n) {
	char buf[40];
	int i, s = 0;
	for (i = 0; i < n && i < 40; i++) {
		buf[i] = (char)p[i];
	}
	for (i = 0; i < n && i < 40; i++) {
		s += buf[i];
	}
	return s;
}
