#include "minunit.h"
#include "../src/malloc.h"
#include <stdint.h>

#define _ 42

MU_TEST(malloc_0_returns_null) {
    void *ptr = foo_malloc(0);
    mu_check(ptr == NULL);
}

MU_TEST(posix_memalign_0_returns_null) {
    void *ptr;
    foo_posix_memalign(&ptr, _, 0);

    mu_check(ptr == NULL);
}

MU_TEST_SUITE(all_tests) {
    MU_RUN_TEST(malloc_0_returns_null);

    MU_RUN_TEST(posix_memalign_0_returns_null);
}

int main() {
    MU_RUN_SUITE(all_tests);
    MU_REPORT();
    return 0;
}