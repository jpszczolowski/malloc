#include "malloc.h"
#include <sys/queue.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/*
  __  __   _   ___ ___  ___  ___ 
 |  \/  | /_\ / __| _ \/ _ \/ __|
 | |\/| |/ _ \ (__|   / (_) \__ \
 |_|  |_/_/ \_\___|_|_\\___/|___/

*/

#define abs(x) ((x) >= 0 ? (x) : -(x))
#define max(a, b) ((a) > (b) ? (a) : (b))

/*
  ___ _____ ___ _   _  ___ _____ _   _ ___ ___ ___ 
 / __|_   _| _ \ | | |/ __|_   _| | | | _ \ __/ __|
 \__ \ | | |   / |_| | (__  | | | |_| |   / _|\__ \
 |___/ |_| |_|_\\___/ \___| |_|  \___/|_|_\___|___/

*/                                   

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

/*
  _  _ ___ _    ___ ___ ___     ___ _   _ _  _  ___ _____ ___ ___  _  _ ___ 
 | || | __| |  | _ \ __| _ \   | __| | | | \| |/ __|_   _|_ _/ _ \| \| / __|
 | __ | _|| |__|  _/ _||   /   | _|| |_| | .` | (__  | |  | | (_) | .` \__ \
 |_||_|___|____|_| |___|_|_\   |_|  \___/|_|\_|\___| |_| |___\___/|_|\_|___/
                                                                          
*/

mem_block_t *get_prev_block(mem_block_t *block_ptr) {
    return (mem_block_t *) *((int64_t *) block_ptr - 1);
}

mem_block_t *get_next_block(mem_block_t *block_ptr) {
    return (mem_block_t *) ((char *) block_ptr + abs(block_ptr->mb_size) + 2 * sizeof(void *));
}

mem_block_t *get_block_start_from_user_ptr(void *user_ptr) {
    int64_t *ptr = (int64_t *) user_ptr;
    do {
        ptr--;
    } while (*ptr == 0);
    return ptr;
}

mem_chunk_t *get_chunk_start_from_block_ptr(mem_block_t *block_ptr) {
    mem_block_t *cur_block_ptr = block_ptr;
    do {
        cur_block_ptr = get_prev_block(cur_block_ptr);
    } while (cur_block_ptr->mb_size != 0);
    // cur_block_ptr is now &chunk_ptr->ma_first

    return (mem_chunk_t *)((char *)cur_block_ptr - 4 * sizeof(void *));
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

// set boundary tag of block_ptr if block_ptr->mb_size is known
void set_boundary_tag(mem_block_t *block_ptr) {
    *(uint64_t *)((char *) block_ptr + abs(block_ptr->mb_size) + sizeof(void *)) = (uint64_t) block_ptr;
}

/*
  ___ __  __ ___ _    ___ __  __ ___ _  _ _____ _ _____ ___ ___  _  _ 
 |_ _|  \/  | _ \ |  | __|  \/  | __| \| |_   _/_\_   _|_ _/ _ \| \| |
  | || |\/| |  _/ |__| _|| |\/| | _|| .` | | |/ _ \| |  | | (_) | .` |
 |___|_|  |_|_| |____|___|_|  |_|___|_|\_| |_/_/ \_\_| |___\___/|_|\_

*/

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
        return NULL;
    }

    return (void *) 42; // TODO
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
    aligned_size = max(aligned_size, 2 * sizeof(void *)); // at least space for mb_node
                                                          // when block becomes free

    if (size > INT32_MAX || aligned_size > INT32_MAX) {
        return ENOMEM;
    }

    mem_block_t *free_block_ptr = find_free_block(aligned_size);

    if (free_block_ptr == NULL) {
        // 3 is from boundary tag at the end and end-empty-block
        size_t mmap_len = aligned_size + sizeof(mem_chunk_t) + 3 * sizeof(void *);
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
        chunk_ptr->ma_first.mb_size = 0; // first empty block in chunk
        chunk_ptr->ma_first.mb_data[0] = (uint64_t) &chunk_ptr->ma_first; // boundary tag -- pointer to first empty block

        fprintf(stderr, "first empty block %p, boundary tag %p\n", &chunk_ptr->ma_first.mb_size,
                (void *) chunk_ptr->ma_first.mb_data[0]);

        mem_block_t *block_ptr = (mem_block_t *) &chunk_ptr->ma_first.mb_data[1]; // first non-empty block
        LIST_INSERT_HEAD(&chunk_ptr->ma_freeblks, block_ptr, mb_node);
        block_ptr->mb_size = chunk_ptr->size - 3 * sizeof(void *);

        int64_t *end_ptr = (int64_t *) (((char *) chunk_ptr) + mmap_len - 8);
        fprintf(stderr, "end_ptr - 1 %p\n", end_ptr - 1);

        *end_ptr = (int64_t) (end_ptr - 1);
        *(end_ptr - 1) = 0;
        *(end_ptr - 2) = (int64_t) block_ptr;

        free_block_ptr = block_ptr;
    }

    void *data = &free_block_ptr->mb_data;
    void *user_ptr = (void *) round_up_to((size_t) data, alignment);
    
    fprintf(stderr, "user_ptr = %p\n", user_ptr);
    
    *memptr = user_ptr;
    
    mem_block_t *block1_ptr = free_block_ptr;
    
    assert(block1_ptr->mb_size > 0);
    int32_t block1_old_size = block1_ptr->mb_size;
    block1_ptr->mb_size = -aligned_size;

    mem_block_t *block2_ptr = (mem_block_t *) ((char *) block1_ptr->mb_data + abs(block1_ptr->mb_size) + sizeof(void *));
    // +boundary tag

    LIST_INSERT_AFTER(block1_ptr, block2_ptr, mb_node);
    LIST_REMOVE(block1_ptr, mb_node);

    fprintf(stderr, "zeroing %lu bytes from %p\n", user_ptr - data, data);
    memset(data, 0, user_ptr - data);

    fprintf(stderr, "block1_ptr %p, block2_ptr %p\n", block1_ptr, block2_ptr);
    
    
    set_boundary_tag(block1_ptr);

    block2_ptr->mb_size = block1_old_size - abs(block1_ptr->mb_size) - 2*sizeof(void *);
    // -boundary tag-block2_ptr->mb_size

    set_boundary_tag(block2_ptr);

    assert(block2_ptr->mb_size >= 2 * sizeof(void *));
    // TODO jak block2 za mały to go nie rób

    return 0;
}

// TODO
void foo_free(void *ptr) {
    #if MALLOC_DEBUG
        fprintf(stderr, "called foo_free(%p)\n", ptr);
    #endif

    if (ptr == NULL) {
        return;
    }

    mem_block_t *block_ptr = get_block_start_from_user_ptr(ptr);
    mem_block_t *next_block_ptr = get_next_block(block_ptr);
    mem_block_t *prev_block_ptr = get_prev_block(block_ptr);

    // fprintf(stderr, "block to free: %p\n", block_ptr);
    // fprintf(stderr, "next block: %p\n", next_block_ptr);
    // fprintf(stderr, "prev block: %p\n", prev_block_ptr);

    block_ptr->mb_size *= -1; // block is now free

    int next_block_free = next_block_ptr->mb_size != 0 && next_block_ptr->mb_size > 0;
    int prev_block_free = prev_block_ptr->mb_size != 0 && prev_block_ptr->mb_size > 0;

    if (next_block_free) {
        block_ptr->mb_size += next_block_ptr->mb_size + 2 * sizeof(void *); // + boundary tag + next_block_ptr->mb_size
        
        if (!prev_block_free) { // if prev_block_free we'll have leave previous block on the list
            set_boundary_tag(block_ptr);
            LIST_INSERT_BEFORE(next_block_ptr, block_ptr, mb_node);
        }

        LIST_REMOVE(next_block_ptr, mb_node);
    }

    if (prev_block_free) {
        prev_block_ptr->mb_size += block_ptr->mb_size + 2 * sizeof(void *);
        set_boundary_tag(prev_block_ptr);
        
        block_ptr = prev_block_ptr;
    }

    if (get_prev_block(block_ptr)->mb_size == 0 && get_next_block(block_ptr)->mb_size == 0) {
        // there is only one block (and it's free) in the chunk, so delete the chunk
        mem_chunk_t *chunk_ptr = get_chunk_start_from_block_ptr(block_ptr);
        LIST_REMOVE(chunk_ptr, ma_node);
        
        size_t length_to_munmap = chunk_ptr->size + sizeof(mem_chunk_t);
        assert(length_to_munmap % getpagesize() == 0);

        munmap(chunk_ptr, length_to_munmap);
    } else if (!prev_block_free && !next_block_free) { // add yourself to the list
        mem_chunk_t *chunk_ptr = get_chunk_start_from_block_ptr(block_ptr);
        
        mem_block_t *cur_block_ptr;
        int added_to_list = 0;
        LIST_FOREACH(cur_block_ptr, &chunk_ptr->ma_freeblks, mb_node) {
            if (cur_block_ptr > block_ptr) {
                LIST_INSERT_BEFORE(cur_block_ptr, block_ptr, mb_node);
                added_to_list = 1;
                break;
            }     
        }
        assert(added_to_list == 1);
    }
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
                fprintf(stderr, "  prev %p, next %p\n", cur_block_ptr->mb_node.le_prev, cur_block_ptr->mb_node.le_next);
            } else if (size < 0) {
                fprintf(stderr, "  occupied\n");
                fprintf(stderr, "  data:\n");
                for (int i = 0; i < abs(size); i++) {
                    fprintf(stderr, "%d(%c) ", *((char *)cur_block_ptr->mb_data + i), *((char *)cur_block_ptr->mb_data + i));
                }
                fprintf(stderr, "\n");
            }

            mem_block_t *prev_block_ptr = cur_block_ptr;
            cur_block_ptr = (mem_block_t *)((char *)cur_block_ptr + abs(size) + 8);
            
            fprintf(stderr, " boundary tag is at address %p\n", cur_block_ptr);
            uint64_t boundary_tag = *(uint64_t *)(cur_block_ptr);
            fprintf(stderr, " boundary tag %p\n\n", (void *) boundary_tag);
            assert(prev_block_ptr == boundary_tag);
            
            cur_block_ptr = (mem_block_t *)((char *)cur_block_ptr + 8);
        }
        
        fprintf(stderr, "free blocks:\n");
        mem_block_t *block_ptr;
        LIST_FOREACH(block_ptr, &chunk_ptr->ma_freeblks, mb_node) {
            fprintf(stderr, " ptr %p, size %d\n", block_ptr, block_ptr->mb_size);          
        }
    }
}