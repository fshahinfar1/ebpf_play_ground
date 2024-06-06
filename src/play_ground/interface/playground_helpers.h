#ifndef PLAYGROUND_HELPERS
#define PLAYGROUND_HELPERS
#include <stdint.h>
// Map access functions
static void *(*lookup)(char *name, const void *key) = (void *)1;
static void *(*lookup_fast)(int index, const void *key_ptr) = (void *)10;
static int (*free_elem)(void *ptr) = (void *)3;
/* For debugging */
static void (*ubpf_print)(char *fmt, ...) = (void *)4;
/* For reading timestamp CPU */
static unsigned long int (*ubpf_rdtsc)(void) = (void *)5;
/* memmove */
static void (*ubpf_memmove)(void *d, void *s, uint32_t n) = (void *)6;
/* Userspace Maps */
static void *(*userspace_lookup)(const void *, const void *) = (void *)7;
static int (*userspace_update)(void *, const void *, void *) = (void *)8;
/* Get time in nanosecond */
static uint64_t (*ubpf_time_get_ns)(void) = (void *)9;
#endif
