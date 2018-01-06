#include <stddef.h>

#define DELETE_FOO 0

#if DELETE_FOO
#define foo_malloc malloc
#define foo_free free
#define foo_calloc calloc
#define foo_realloc realloc
#endif

void *foo_malloc(size_t size);
void *foo_calloc(size_t count, size_t size);
void *foo_realloc(void *ptr, size_t size);
int foo_posix_memalign(void **memptr, size_t alignment, size_t size);
void foo_free(void *ptr);