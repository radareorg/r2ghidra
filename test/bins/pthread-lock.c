// ELF imports carry no library name: with r2ghidra.ccode=true the whole import
// name must be kept (pthread_mutex_lock, not mutex_lock).
extern int pthread_mutex_lock(void *);
int lock_wrap(void *m) { return pthread_mutex_lock(m); }
