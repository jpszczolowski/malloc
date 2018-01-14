#ifndef JULIAN_MALLOC
#define JULIAN_MALLOC

#include <stddef.h>

#define MALLOC_DEBUG 0
#define DELETE_FOO 1

#if DELETE_FOO
    #define foo_malloc malloc
    #define foo_calloc calloc
    #define foo_realloc realloc
    #define foo_posix_memalign posix_memalign
    #define foo_free free
#endif

void *foo_malloc(size_t size);
void *foo_calloc(size_t count, size_t size);
void *foo_realloc(void *ptr, size_t size);
int foo_posix_memalign(void **memptr, size_t alignment, size_t size);
void foo_free(void *ptr);
void mdump();
void check_mem_integrity();

#endif