#include "malloc.h"
#include <sys/queue.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>

typedef struct mem_block {
    int32_t mb_size; // mb_size > 0 => free, mb_size < 0 => allocated
    union {
        LIST_ENTRY(mem_block) mb_node; // node on free block list, valid if block is free
        uint64_t mb_data[0]; // user data pointer, valid if block is allocated
    };
} mem_block_t;

typedef struct mem_chunk {
    LIST_ENTRY(mem_chunk) ma_node; // node on list of all chunks
    LIST_HEAD(, mem_block) ma_freeblks; // list of all free blocks in the chunk
    int32_t size; // chunk size minus sizeof(mem_chunk_t)
    mem_block_t ma_first; // first block in the chunk
} mem_chunk_t;

LIST_HEAD(, mem_chunk) chunk_list; // list of all chunks

int foo_posix_memalign(void **memptr, size_t alignment, size_t size) {
    #if MALLOC_DEBUG
        fprintf(stderr, "called foo_posix_memalign(%p, %lu, %lu)\n", memptr, alignment, size);
    #endif

    if (size == 0) {
        *memptr = NULL;
    }
}

void *foo_malloc(size_t size) {
    #if MALLOC_DEBUG
        fprintf(stderr, "called foo_malloc(%lu)\n", size);
    #endif

    void *ptr;
    int ret = foo_posix_memalign(&ptr, sizeof(void *), size);
    switch (ret) {
        case ENOMEM: // There was insufficient memory to fulfill the allocation request.
            errno = ENOMEM;
            return NULL;
        case 0: // success
            return ptr;
        default:
        case EINVAL: // The alignment argument was not a power of two, or was not a multiple of sizeof(void *).
            assert(0);
    }
}


void *foo_calloc(size_t count, size_t size) { 
    #if MALLOC_DEBUG
        fprintf(stderr, "called foo_calloc(%lu, %lu)\n", count, size);
    #endif

}

void *foo_realloc(void *ptr, size_t size) {
    #if MALLOC_DEBUG
        fprintf(stderr, "called foo_realloc(%p, %lu)\n", ptr, size);
    #endif

}

void foo_free(void *ptr) {
    #if MALLOC_DEBUG
        fprintf(stderr, "called foo_free(%p)\n", ptr);
    #endif

}

// Udostępnij procedurę mdump drukującą stan menadżera pamięci – tj. listy wszystkich obszarów oraz bloków.    
void mdump() {

}