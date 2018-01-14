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

char __debug_buf__[256];
#define debug_force(format, args...) do { \
    snprintf(__debug_buf__, sizeof(__debug_buf__), format, args); \
    write(STDERR_FILENO, __debug_buf__, strlen(__debug_buf__)); \
    fflush(stderr); } while (0);

#define debug(format, args...) if (MALLOC_DEBUG) { debug_force(format, args); }

#define abs(x) ((x) >= 0 ? (x) : -(x))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

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

extern inline mem_block_t *get_prev_block(mem_block_t *block_ptr) {
    return (mem_block_t *) *((int64_t *) block_ptr - 1);
}

extern inline mem_block_t *get_next_block(mem_block_t *block_ptr) {
    return (mem_block_t *) ((char *) block_ptr + abs(block_ptr->mb_size) + 2 * sizeof(void *));
}

extern inline mem_block_t *get_block_start_from_user_ptr(void *user_ptr) {
    int64_t *ptr = (int64_t *) user_ptr;
    do {
        ptr--;
    } while (*ptr == 0);
    return (mem_block_t *) ptr;
}

extern inline mem_chunk_t *get_chunk_start_from_block_ptr(mem_block_t *block_ptr) {
    debug("called get_chunk_start_from_block_ptr(%p)\n", block_ptr);

    mem_block_t *cur_block_ptr = block_ptr;
    do {
        cur_block_ptr = get_prev_block(cur_block_ptr);
    } while (cur_block_ptr->mb_size != 0);
    // cur_block_ptr is now &chunk_ptr->ma_first

    mem_chunk_t *ret = (mem_chunk_t *)((char *)cur_block_ptr - 4 * sizeof(void *));
    debug("get_chunk_start_from_block_ptr(%p) returned %p\n", block_ptr, ret);
    return ret;
}

mem_block_t *find_free_block(int32_t size) {
    debug("called find_free_block(%d)\n", size);
    assert(size > 0);

    mem_chunk_t *chunk_ptr;
    LIST_FOREACH(chunk_ptr, &chunk_list, ma_node) {
        mem_block_t *block_ptr;
        LIST_FOREACH(block_ptr, &chunk_ptr->ma_freeblks, mb_node) {
            if (block_ptr->mb_size >= size) {
                debug("find_free_block(%d) returned %p\n", size, block_ptr);
                return block_ptr;
            }
        }
    }

    return NULL;
}

extern inline size_t round_up_to(size_t number, size_t multiple) {
    return (number + multiple - 1) / multiple * multiple;
}

// get boundary tag address of block_ptr if block_ptr->mb_size is known
extern inline void *get_boundary_tag_addr(mem_block_t *block_ptr) {
    return (void *) ((char *) block_ptr + abs(block_ptr->mb_size) + sizeof(void *));
}

// set boundary tag of block_ptr if block_ptr->mb_size is known
extern inline void set_boundary_tag(mem_block_t *block_ptr) {
    *(uint64_t *) get_boundary_tag_addr(block_ptr) = (uint64_t) block_ptr;
}

mem_block_t *create_chunk_and_return_free_block_ptr(size_t size) {    
    debug("called create_chunk_and_return_free_block_ptr(%lu)\n", size);

    size_t mmap_len = sizeof(mem_chunk_t) + size + 3 * sizeof(void *);
    // header & data & boundary tag & empty block at the end
    mmap_len = round_up_to(mmap_len, getpagesize());

    assert(mmap_len > 0);
    mem_chunk_t *chunk_ptr = mmap(NULL, mmap_len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        
    if (chunk_ptr == MAP_FAILED) {
        assert(errno == ENOMEM || errno == EINVAL);
        return NULL;
    }

    chunk_ptr->size = mmap_len - sizeof(mem_chunk_t);
    
    mem_block_t *first_empty_block_ptr = &chunk_ptr->ma_first;
    first_empty_block_ptr->mb_size = 0;
    set_boundary_tag(first_empty_block_ptr);

    LIST_INSERT_HEAD(&chunk_list, chunk_ptr, ma_node);
    LIST_INIT(&chunk_ptr->ma_freeblks);

    mem_block_t *free_block_ptr = get_boundary_tag_addr(first_empty_block_ptr) + sizeof(void *);
    free_block_ptr->mb_size = chunk_ptr->size - 3 * sizeof(void *);
    set_boundary_tag(free_block_ptr);

    LIST_INSERT_HEAD(&chunk_ptr->ma_freeblks, free_block_ptr, mb_node);

    mem_block_t *last_empty_block = get_boundary_tag_addr(free_block_ptr) + sizeof(void *);
    last_empty_block->mb_size = 0;
    set_boundary_tag(last_empty_block);

    return free_block_ptr;
}

/*
  ___ __  __ ___ _    ___ __  __ ___ _  _ _____ _ _____ ___ ___  _  _ 
 |_ _|  \/  | _ \ |  | __|  \/  | __| \| |_   _/_\_   _|_ _/ _ \| \| |
  | || |\/| |  _/ |__| _|| |\/| | _|| .` | | |/ _ \| |  | | (_) | .` |
 |___|_|  |_|_| |____|___|_|  |_|___|_|\_| |_/_/ \_\_| |___\___/|_|\_

*/

void *foo_malloc(size_t size) {
    debug("called foo_malloc(%lu)\n", size);

    void *ptr;
    int ret = foo_posix_memalign(&ptr, sizeof(void *), size);
    switch (ret) {
        case ENOMEM: // There was insufficient memory to fulfill the allocation request.
            errno = ENOMEM;
            return NULL;
        case 0: // success
            return ptr;
        default:
            assert(0);
    }
}

void *foo_calloc(size_t count, size_t size) { 
    debug("called foo_calloc(%lu, %lu)\n", count, size);

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

void *foo_realloc(void *ptr, size_t size) {
    debug("called foo_realloc(%p, %lu)\n", ptr, size);

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

    if (size > INT32_MAX) {
        errno = ENOMEM;
        return NULL;
    }

    mem_block_t *block_ptr = get_block_start_from_user_ptr(ptr);
    void *boundary_tag = get_boundary_tag_addr(block_ptr);
    int32_t available_length = (int32_t) boundary_tag - (int32_t) ptr;
    
    debug("available_length %d\n", available_length);

    if ((int32_t) size > available_length) {
        void *new_ptr = foo_malloc(size);
        memcpy(new_ptr, ptr, min((int32_t) size, available_length));
        foo_free(ptr);
        ptr = new_ptr;
    }

    // TODO check whether or not next block is empty

    return ptr;
}

int foo_posix_memalign(void **memptr, size_t alignment, size_t size) {
    debug("called foo_posix_memalign(%p, %lu, %lu)\n", memptr, alignment, size);

    if (size == 0) {
        *memptr = NULL;
        return 0;
    }

    // The alignment argument was not a power of two, or was not a multiple of sizeof(void *)
    if ((alignment & (alignment - 1)) || alignment % sizeof(void *) != 0) {
        return EINVAL;
    }

    if (size > INT32_MAX) {
        return ENOMEM;
    }

    size += alignment; // we must be able to choose address that is multiple of alignment
    size = round_up_to(size, sizeof(void *));
    size = max(size, 2 * sizeof(void *)); // at least space for mb_node
                                          // when block becomes free

    if (size > INT32_MAX) {
        return ENOMEM;
    }

    int32_t size32 = size;
    mem_block_t *free_block_ptr = find_free_block(size32);

    if (free_block_ptr == NULL) {
        free_block_ptr = create_chunk_and_return_free_block_ptr(size32);
    }

    if (free_block_ptr == NULL) {
        return ENOMEM;
    }
    
    assert(free_block_ptr->mb_size > 0);

    // now we'll split free block into block1 and block2
    // we'll return block1 to the user and keep free block2 for future use

    mem_block_t *block1_ptr = free_block_ptr;
    
    void *block1_data = &block1_ptr->mb_data;
    void *user_ptr_to_ret = (void *) round_up_to((size_t) block1_data, alignment);

    int32_t probable_block2_size = block1_ptr->mb_size - size32 - 2 * (int32_t) sizeof(void *);
    int32_t minimum_possible_block_size = 2 * sizeof(void *);

    if (probable_block2_size < minimum_possible_block_size) {
        // this block is too small to split it into occupied and another free block
        // so just use it
        
        LIST_REMOVE(block1_ptr, mb_node);
        block1_ptr->mb_size *= -1;
    } else {
        // block big enough to split

        block1_ptr->mb_size = -size32;
        set_boundary_tag(block1_ptr);

        mem_block_t *block2_ptr = get_boundary_tag_addr(block1_ptr) + sizeof(void *);
        block2_ptr->mb_size = probable_block2_size;
        set_boundary_tag(block2_ptr);

        LIST_INSERT_AFTER(block1_ptr, block2_ptr, mb_node);
        LIST_REMOVE(block1_ptr, mb_node);

        assert((unsigned long) block2_ptr->mb_size >= 2 * sizeof(void *));
    }
    
    assert((size_t) user_ptr_to_ret % alignment == 0);
    assert(block1_ptr->mb_size < 0);
    
    memset(block1_data, 0, user_ptr_to_ret - block1_data);
    *memptr = user_ptr_to_ret;
    return 0;
}

void foo_free(void *ptr) {
    debug("called foo_free(%p)\n", ptr);

    if (ptr == NULL) {
        return;
    }

    mem_block_t *block_ptr = get_block_start_from_user_ptr(ptr);
    mem_block_t *next_block_ptr = get_next_block(block_ptr);
    mem_block_t *prev_block_ptr = get_prev_block(block_ptr);

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

        debug("called munmap(%p, %lu)\n", chunk_ptr, length_to_munmap);
        int munmap_ret = munmap(chunk_ptr, length_to_munmap);
        assert(munmap_ret == 0);
    } else if (!prev_block_free && !next_block_free) { // add yourself to the list
        mem_chunk_t *chunk_ptr = get_chunk_start_from_block_ptr(block_ptr);

        mem_block_t *cur_block_ptr;
        int added_to_list = 0;

        if (LIST_EMPTY(&chunk_ptr->ma_freeblks)) {
            LIST_INSERT_HEAD(&chunk_ptr->ma_freeblks, block_ptr, mb_node);
            added_to_list = 1;
        } else {
            LIST_FOREACH(cur_block_ptr, &chunk_ptr->ma_freeblks, mb_node) {
                if (cur_block_ptr > block_ptr) {
                    LIST_INSERT_BEFORE(cur_block_ptr, block_ptr, mb_node);
                    added_to_list = 1;
                    break;
                }     
            }
        }

        assert(added_to_list == 1);
    }
}

void check_mem() {
    mem_chunk_t *chunk_ptr;
    LIST_FOREACH(chunk_ptr, &chunk_list, ma_node) {        
        mem_block_t *cur_block_ptr = &chunk_ptr->ma_first;
        int cnt_size_0 = 0;
        while (cnt_size_0 != 2) {
            cnt_size_0 += (cur_block_ptr->mb_size == 0);

            mem_block_t *prev_block_ptr = cur_block_ptr;
            cur_block_ptr = get_boundary_tag_addr(cur_block_ptr);
            
            uint64_t boundary_tag = *(uint64_t *)(cur_block_ptr);
            assert((uint64_t) prev_block_ptr == boundary_tag);
            
            cur_block_ptr = (mem_block_t *)((char *)cur_block_ptr + sizeof(void *));
        }
        
        mem_block_t *block_ptr;
        LIST_FOREACH(block_ptr, &chunk_ptr->ma_freeblks, mb_node) {
            assert(block_ptr->mb_size > 0);          
        }
    }    
}

void mdump() {
    debug("%s", "called mdump()\n");
    debug("%s", "------------------------------------------------------------------------------------------" \
                "------------------------------------------------------------------------------------------" \
                "-------------------------\n");

    
    mem_chunk_t *chunk_ptr;
    LIST_FOREACH(chunk_ptr, &chunk_list, ma_node) {
        debug_force("chunk_ptr %p, size %d\n", chunk_ptr, chunk_ptr->size);
        debug_force("\t%s", "all blocks:\n");
        
        mem_block_t *cur_block_ptr = &chunk_ptr->ma_first;
        int cnt_size_0 = 0;
        while (cnt_size_0 != 2) {
            int32_t size = cur_block_ptr->mb_size;
            debug_force("\t\tptr %p, size %d\n", cur_block_ptr, size);
            
            cnt_size_0 += (size == 0);

            if (size > 0) {
                debug_force("%s", "\t\t\tfree\n");
                debug_force("\t\t\tprev %p, next %p\n", cur_block_ptr->mb_node.le_prev, cur_block_ptr->mb_node.le_next);
            } else if (size < 0) {
                debug_force("%s", "\t\t\toccupied\n");
                // debug_force("%s", "\t\t\tdata: ");
                // for (int i = 0; i < abs(size); i++) {
                //     char data_byte = *((char *)cur_block_ptr->mb_data + i);
                //     if (data_byte == 0) {
                //         debug_force("%s", "0() ");
                //     } else {
                //         debug_force("%d(%c) ", data_byte, data_byte);
                //     }
                // }
                // debug_force("%s", "\n");
            }

            mem_block_t *prev_block_ptr = cur_block_ptr;
            cur_block_ptr = get_boundary_tag_addr(cur_block_ptr);
            
            uint64_t boundary_tag = *(uint64_t *)(cur_block_ptr);
            debug_force("\t\tboundary tag %p\n\n", (void *) boundary_tag);
            assert((uint64_t) prev_block_ptr == boundary_tag);
            
            cur_block_ptr = (mem_block_t *)((char *)cur_block_ptr + sizeof(void *));
        }
        
        debug_force("%s", "\tfree blocks:\n");
        mem_block_t *block_ptr;
        LIST_FOREACH(block_ptr, &chunk_ptr->ma_freeblks, mb_node) {
            debug_force("\t\tptr %p, size %d\n", block_ptr, block_ptr->mb_size);
            assert(block_ptr->mb_size > 0);          
        }
    }
}