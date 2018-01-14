#include "minunit.h"
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
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
    static void check_mem() { }
#else
    #include "../src/malloc.h"
#endif

MU_TEST(simple_allocating_and_freeing) {
    int cnt = 100;
    int alloc_size_max = 1 << 15;
    void *ptr[cnt];

    srand(time(NULL));

    for (int i = 0; i < cnt; i++) {
        int size_to_alloc = rand() % alloc_size_max + 1;
        ptr[i] = foo_malloc(size_to_alloc);
        memset(ptr[i], 'X', size_to_alloc);
        mu_check(ptr[i] != NULL);
        check_mem();
    }

    for (int i = 0; i < cnt; i++) {
        foo_free(ptr[i]);
        check_mem();
    }
}

int first_empty(void *ptr[], int size) {
    for (int i = 0; i < size; i++) {
        if (ptr[i] == NULL) {
            return i;
        }
    }
    return -1;
}

int first_non_empty(void *ptr[], int size) {
    for (int i = 0; i < size; i++) {
        if (ptr[i] != NULL) {
            return i;
        }
    }
    return -1;
}

#define SIZE 1000000
void *ptr[SIZE];
int allocated_size[SIZE];

MU_TEST(all_functions_randomly_interleaved) {
    memset(ptr, 0, sizeof(ptr));

    srand(time(NULL));

    int alloc_size_max = 1 << 10;
    int actions = 500 * 1000;
    while (actions--) {
        int action = rand() % 6;
        int idx;
        if (action <= 2) { // malloc, calloc, posix_memalign
            idx = first_empty(ptr, SIZE);
        } else { // free or realloc
            idx = first_non_empty(ptr, SIZE);
        }

        if (idx == -1) {
            continue;
        }

        int size_to_alloc = rand() % alloc_size_max + 1;
        
        if (action == 0) { // MALLOC (1/6 = 16.7%)
            ptr[idx] = foo_malloc(size_to_alloc);
            allocated_size[idx] = size_to_alloc;
        } else if (action == 1) { // CALLOC (1/6 = 16.7%)
            ptr[idx] = foo_calloc(size_to_alloc, sizeof(int));
            allocated_size[idx] = size_to_alloc * sizeof(int);
            for (int i = 0; i < size_to_alloc; i++) {
                mu_check(*((int *) ptr[idx] + i) == 0);
            }
        } else if (action == 2) { // POSIX_MEMALIGN (1/6 = 16.7%)
            int alignment = 1 << (3 + rand() % 5);
            void *new_ptr;
            mu_check(!foo_posix_memalign(&new_ptr, alignment, size_to_alloc));
            mu_check((uint32_t) new_ptr % alignment == 0);

            ptr[idx] = new_ptr;
            allocated_size[idx] = size_to_alloc;
        } else if (action == 3) { // REALLOC (1/6 = 16.7%)
            void *new_ptr = foo_realloc(ptr[idx], size_to_alloc);
            if (size_to_alloc <= allocated_size[idx]) {
                mu_check(new_ptr == ptr[idx]);
            }
            ptr[idx] = new_ptr;
            allocated_size[idx] = size_to_alloc;
        } else if (action >= 4) { // FREE (2/6 = 33.3%)
            memset(ptr[idx], 'X', allocated_size[idx]);
            foo_free(ptr[idx]);
            ptr[idx] = NULL;
        }

        if (action <= 3) { // allocating
            memset(ptr[idx], 'X', allocated_size[idx]);
        }
        check_mem();
    }

    for (int i = 0; i < SIZE; i++) {
        if (ptr[i] != NULL) {
            memset(ptr[i], 'X', allocated_size[i]);
            foo_free(ptr[i]);
            ptr[i] = NULL;
            check_mem();
        }
    }
}

MU_TEST_SUITE(all_tests) {
    MU_RUN_TEST(simple_allocating_and_freeing);    
    MU_RUN_TEST(all_functions_randomly_interleaved);
}

int main() {
    MU_RUN_SUITE(all_tests);
    MU_REPORT();
    return 0;
}