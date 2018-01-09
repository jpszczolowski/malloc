#include "malloc.h"
#include <sys/queue.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

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
int chunk_list_size;

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

    if (count == 0 || size == 0) {
        return NULL;
    }

    size_t bytes = count * size;
    if (bytes / size != count) {
        errno = ENOMEM;
        return NULL;
    }

    void *ptr = foo_malloc(bytes); // bytes > 0
    if (ptr == NULL) {
        assert(errno == ENOMEM);
        return NULL;
    }
    
    memset(ptr, 0, bytes);    

    return ptr;
}

// TODO
void *foo_realloc(void *ptr, size_t size) {
    #if MALLOC_DEBUG
        fprintf(stderr, "called foo_realloc(%p, %lu)\n", ptr, size);
    #endif

    if (ptr == NULL && size == 0) {
        return NULL;
    }

    if (ptr == NULL) {
        void *ptr_from_malloc = foo_malloc(size); // size > 0
        if (ptr_from_malloc == NULL) {
            assert(errno == ENOMEM);
            return NULL;
        }
        return ptr_from_malloc;
    }

    if (size == 0) {
        foo_free(ptr);
        return NULL; // ???
    }

    return (void *) 42; // TODO
}

mem_block_t *find_free_block(int32_t size) {
    #if MALLOC_DEBUG
        fprintf(stderr, "called find_free_block(%d)\n", size);
    #endif    

    assert(size > 0);

    mem_chunk_t *chunk_ptr;
    LIST_FOREACH(chunk_ptr, &chunk_list, ma_node) {
        mem_block_t *block_ptr;
        LIST_FOREACH(block_ptr, &chunk_ptr->ma_freeblks, mb_node) {
            if (block_ptr->mb_size >= size) {
                #if MALLOC_DEBUG
                    fprintf(stderr, "find_free_block(%d) returned %p\n", size, block_ptr);
                #endif
                return block_ptr;
            }
        }
    }

    #if MALLOC_DEBUG
        fprintf(stderr, "find_free_block(%d) returned %p\n", size, NULL);
    #endif
    return NULL;
}

size_t round_up_to(size_t number, size_t multiple) {
    return (number + multiple - 1) / multiple * multiple;
}

// TODO
int foo_posix_memalign(void **memptr, size_t alignment, size_t size) {
    #if MALLOC_DEBUG
        fprintf(stderr, "called foo_posix_memalign(%p, %lu, %lu)\n", memptr, alignment, size);
    #endif

    if (size == 0) {
        *memptr = NULL;
        return 0;
    }

    // The alignment argument was not a power of two, or was not a multiple of sizeof(void *)
    if ((alignment & (alignment - 1)) || alignment % sizeof(void *) != 0) {
        return EINVAL;
    }

    size_t aligned_size = round_up_to(alignment - sizeof(void *) + size, sizeof(void *));

    if (aligned_size > INT32_MAX) {
        return ENOMEM;
    }

    mem_block_t *free_block_ptr = find_free_block(aligned_size);

    if (free_block_ptr == NULL) {
        size_t mmap_len = aligned_size + sizeof(mem_chunk_t) + sizeof(void *); // boundary tag
        mmap_len = round_up_to(mmap_len, getpagesize());
        fprintf(stderr, "mmap_len = %lu\n", mmap_len);

        assert(mmap_len > 0);
        mem_chunk_t *chunk_ptr = mmap(NULL, mmap_len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        
        fprintf(stderr, "chunk_ptr = %p\n", chunk_ptr);

        if (chunk_ptr == MAP_FAILED) {
            assert(errno == ENOMEM || errno == EINVAL);
            return ENOMEM;
        }

        LIST_INSERT_HEAD(&chunk_list, chunk_ptr, ma_node);
        chunk_ptr->size = mmap_len - sizeof(mem_chunk_t);
        LIST_INIT(&chunk_ptr->ma_freeblks);
        chunk_ptr->ma_first.mb_size = 0; // first block in chunk
        chunk_ptr->ma_first.mb_data[0] = (uint64_t) &chunk_ptr->ma_first; // boundary tag -- pointer to first block

        mem_block_t *block_ptr = (mem_block_t *) &chunk_ptr->ma_first.mb_data[1]; // first non-empty block
        LIST_INSERT_HEAD(&chunk_ptr->ma_freeblks, block_ptr, mb_node);

        free_block_ptr = block_ptr;
    }

    void *data = &free_block_ptr->mb_data;
    void *user_ptr = (void *) round_up_to((size_t) data, alignment);
    memset(data, 0, user_ptr - data);
    
    fprintf(stderr, "user_ptr = %p\n", user_ptr);
    
    *memptr = user_ptr;
    return 0;
}


// TODO
void foo_free(void *ptr) {
    #if MALLOC_DEBUG
        fprintf(stderr, "called foo_free(%p)\n", ptr);
    #endif

}

// TODO
void mdump() {
    #if MALLOC_DEBUG
        fprintf(stderr, "called mdump()\n");
    #endif

    mem_chunk_t *chunk_ptr;
    LIST_FOREACH(chunk_ptr, &chunk_list, ma_node) {
        fprintf(stderr, "chunk_ptr %p, size %d, &ma_first %p\n", chunk_ptr, chunk_ptr->size, &chunk_ptr->ma_first);
        
        fprintf(stderr, "all blocks:\n");
        mem_block_t *cur_block_ptr = &chunk_ptr->ma_first;
        int cnt_size_0 = 0;
        while (cnt_size_0 != 2) {
            int32_t size = cur_block_ptr->mb_size;
            fprintf(stderr, " ptr %p, size %d\n", cur_block_ptr, size);
            
            cnt_size_0 += (size == 0);

            if (size > 0) {
                fprintf(stderr, "  free\n");
                fprintf(stderr, "  prev %p, next %p\n", cur_block_ptr->mb_node.le_next, *cur_block_ptr->mb_node.le_prev);
            } else if (size < 0) {
                fprintf(stderr, "  occupied\n");
                fprintf(stderr, "  data:\n");
                for (int i = 0; i < size; i++) {
                    fprintf(stderr, "%lu", cur_block_ptr->mb_data[i]);
                }
                fprintf(stderr, "\n");
            }

            cur_block_ptr += size + 1;
            fprintf(stderr, " boundary tag %p\n", (void *) *(uint64_t *)(cur_block_ptr));
            cur_block_ptr++;
        }
        
        fprintf(stderr, "free blocks:\n");
        mem_block_t *block_ptr;
        LIST_FOREACH(block_ptr, &chunk_ptr->ma_freeblks, mb_node) {
            fprintf(stderr, " ptr %p, size %d\n", block_ptr, block_ptr->mb_size);          
            
            if (block_ptr->mb_size < 0) {
                fprintf(stderr, "block_ptr->mb_data:\n");
                for (int i = 0; i < block_ptr->mb_size; i++) {
                    fprintf(stderr, "%lu", block_ptr->mb_data[i]);
                }
            } 
        }
    }
}