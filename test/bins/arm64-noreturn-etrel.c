#include <stdlib.h>
#include <string.h>

int sum(const char *s) {
	char buf[32];
	strncpy (buf, s, sizeof (buf) - 1);
	buf[sizeof (buf) - 1] = 0;
	int r = 0;
	for (char *p = buf; *p; p++) {
		r += *p;
	}
	return r;
}

void quit(void) {
	exit (42);
}
