#include <err.h>

extern void custom_fatal(int status) __attribute__((noreturn));

void call_err(void) {
	err (42, "boom");
}

void call_errx(void) {
	errx (42, "boom");
}

void call_custom(void) {
	custom_fatal (42);
}
