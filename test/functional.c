#include "minunit.h"
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <stdlib.h>

#define TEST_GLIBC_MALLOC 0

#if TEST_GLIBC_MALLOC
    #include <malloc.h>
    #include <stdlib.h>
    #define foo_malloc malloc
    #define foo_calloc calloc
    #define foo_realloc realloc
    #define foo_posix_memalign posix_memalign
    #define foo_free free
#else
    #include "../src/malloc.h"
#endif

MU_TEST(allocating_and_freeing) {
    int cnt = 1000;
    int size = 1 << 15; // 1B to 32 kB
    void *ptr[cnt];

    srand(time(NULL));

    for (int i = 0; i < cnt; i++) {
        ptr[i] = foo_malloc(rand() % size + 1);
        mu_check(ptr[i] != NULL);
    }

    for (int i = 0; i < cnt; i++) {
        foo_free(ptr[i]);
    }
}

MU_TEST_SUITE(all_tests) {
    MU_RUN_TEST(allocating_and_freeing);

}

int main() {
    MU_RUN_SUITE(all_tests);
    MU_REPORT();
    return 0;
}