#include <stdio.h>
#include "src/malloc.h"
#include <assert.h>
#include <string.h>

#define LONG_DASH_LINE "--------------------------------------------------------------------------"

#define wrap_posix_memalign(alignment, size) do { \
        assert(foo_posix_memalign((void *)&ptr, alignment, size) == 0); \
        fprintf(stderr, "foo_posix_memalign(&ptr, %lu, %lu) returned %p\n", alignment, size, ptr); \
    } while (0);

#define dump() do { \
        mdump(); \
        fprintf(stderr, LONG_DASH_LINE "\n"); \
    } while (0);

int main() {
    int *ptr;

    wrap_posix_memalign(32, 128);
    memset(ptr, 'a', 128);
    dump();

    int *other_ptr1 = ptr;
    
    wrap_posix_memalign(16, 1);
    memset(ptr, 'b', 1);
    dump();

    int *other_ptr2 = ptr;

    wrap_posix_memalign(8, 3);
    memset(ptr, 'c', 3);
    dump();
    
    int *other_ptr3 = ptr;

    wrap_posix_memalign(8, 20);
    memset(ptr, 'd', 20);
    dump();

    int *other_ptr4 = ptr;
    
    wrap_posix_memalign(256, 1);
    memset(ptr, 'd', 1);
    dump();

    foo_free(other_ptr2);
    dump();
    foo_free(other_ptr1);
    dump();
    foo_free(ptr);
    dump();
    foo_free(other_ptr3);
    dump();
    foo_free(other_ptr4);
    dump();

    return 0;
}