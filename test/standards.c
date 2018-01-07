#include "minunit.h"
#include <stdint.h>
#include <errno.h>
#include <limits.h>

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

MU_TEST(malloc_0_returns_null) {
    void *ptr = foo_malloc(0);
    mu_check(ptr == NULL);
}

MU_TEST(malloc_infinity_returns_enomem) {
    void *ptr = foo_malloc(ULLONG_MAX);
    mu_check(ptr == NULL);
    mu_check(errno == ENOMEM);
}

MU_TEST(posix_memalign_0_returns_null) {
    void *ptr;
    int ret = foo_posix_memalign(&ptr, sizeof(void *), 0);

    mu_check(ret == 0);
    mu_check(ptr == NULL);
}

MU_TEST(posix_memalign_infinity_returns_enomem) {
    void *ptr;
    int ret = foo_posix_memalign(&ptr, sizeof(void *), ULLONG_MAX);
    
    mu_check(ret == ENOMEM);
}

MU_TEST(posix_memalign_bad_alignment_returns_einval_1) {
    void *ptr;
    int ret = foo_posix_memalign(&ptr, sizeof(void *)/2, 1); // The alignment was not a multiple of sizeof(void *)

    mu_check(ret == EINVAL);
}

MU_TEST(posix_memalign_bad_alignment_returns_einval_2) {
    void *ptr;
    int ret = foo_posix_memalign(&ptr, 42, 1); // The alignment argument was not a power of two

    mu_check(ret == EINVAL);
}

MU_TEST(calloc_size_0_returns_null) {
    void *ptr = foo_calloc(1, 0);
    
    mu_check(ptr == NULL);
}

MU_TEST(calloc_count_0_returns_null) {
    void *ptr = foo_calloc(0, sizeof(int));
    
    mu_check(ptr == NULL);
}

MU_TEST(calloc_infinity_returns_enomem) {
    void *ptr = foo_calloc(ULLONG_MAX, ULLONG_MAX);

    mu_check(ptr == NULL);
    mu_check(errno == ENOMEM);
}

MU_TEST(calloc_sets_memory_to_zero) {
    int count = 42;
    int *ptr = foo_calloc(count, sizeof(int));
    
    mu_check(ptr != NULL);
    for (int i = 0; i < count; i++) {
        mu_check(ptr[i] == 0);
    }
    foo_free(ptr);
}

static int realloc_size_from, realloc_size_to;
#define min(a, b) ((a) < (b) ? (a) : (b))
MU_TEST(realloc_doesnt_change_content) {
    int some_constant = 0x8BADF00D;

    int *ptr = foo_malloc(realloc_size_from * sizeof(int));
    for (int i = 0; i < realloc_size_from; i++) {
        ptr[i] = some_constant;
    }

    ptr = foo_realloc(ptr, realloc_size_to * sizeof(int));
    for (int i = 0; i < min(realloc_size_from, realloc_size_to); i++) {
        mu_check(ptr[i] == some_constant);
    }

    foo_free(ptr);
}

MU_TEST(realloc_infinity_returns_enomem) {
    int *ptr = foo_malloc(1);
    mu_check(ptr != NULL);

    ptr = foo_realloc(ptr, ULLONG_MAX);
    
    mu_check(ptr == NULL);
    mu_check(errno == ENOMEM);
    foo_free(ptr);   
}

MU_TEST_SUITE(all_tests) {
    MU_RUN_TEST(malloc_0_returns_null);
    MU_RUN_TEST(malloc_infinity_returns_enomem);

    MU_RUN_TEST(posix_memalign_0_returns_null);
    MU_RUN_TEST(posix_memalign_infinity_returns_enomem);
    MU_RUN_TEST(posix_memalign_bad_alignment_returns_einval_1);
    MU_RUN_TEST(posix_memalign_bad_alignment_returns_einval_2);

    MU_RUN_TEST(calloc_size_0_returns_null);
    MU_RUN_TEST(calloc_count_0_returns_null);
    MU_RUN_TEST(calloc_infinity_returns_enomem);
    MU_RUN_TEST(calloc_sets_memory_to_zero);

    MU_RUN_TEST(realloc_infinity_returns_enomem);
    realloc_size_from = 100;
    realloc_size_to = 10000;
    MU_RUN_TEST(realloc_doesnt_change_content);
    realloc_size_from = 10000;
    realloc_size_to = 100;
    MU_RUN_TEST(realloc_doesnt_change_content);
}

int main() {
    MU_RUN_SUITE(all_tests);
    MU_REPORT();
    return 0;
}