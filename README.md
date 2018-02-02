# malloc
Implementation of malloc library (malloc, free and a few other functions) that can be used in regular applications like vim, ls or firefox (just tell the dynamic linker to use it instead of glibc).

### Description
This memory allocator uses double-linked lists to keep track of free blocks. Finding a block is a simple first-fit algorithm. When there is no free block (or not big enough free block), it asks kernel for some new pages (using `mmap`) and creates a new block chunk. Empty chunks are `unmmap`ed.

### Implemented funtions
There are 5 main functions in `src/malloc.c`:
```c
void *foo_malloc(size_t size);
void *foo_calloc(size_t count, size_t size);
void *foo_realloc(void *ptr, size_t size);
int foo_posix_memalign(void **memptr, size_t alignment, size_t size);
void foo_free(void *ptr);
```
and they are conforming to POSIX and C standards.

Functions are prefixed with `foo_` to prevent interference with glibc during development and testing. In `src/malloc.h` you will find macros
```c
#define DELETE_FOO 1

#if DELETE_FOO
    #define foo_malloc malloc
    #define foo_calloc calloc
    #define foo_realloc realloc
    #define foo_posix_memalign posix_memalign
    #define foo_free free
#endif
```
that delete this prefix.

### How to use it in regular app

For example, to run `vim` that uses this malloc implementation, type:
```bash
$ make
```
It will create `build/malloc.so` shared library. Now you have to simply run `vim` with `LD_PRELOAD` environment variable set, that will tell the dynamic linker that this shared ELF should be loaded before all others.
```bash
$ LD_PRELOAD=$PWD/build/malloc.so vim
```
Feel free to try it on `ls`, `xeyes`, `gnome-calculator`, `firefox` or `nautilus`.

### Tests
In `tests` folder you will find two tests:
- `functional.c` that checks some randomly interleaved scenario (as well as memory integrity after each action),
- `standards.c` that cheks conformnance to standards, e.g. whether `calloc` sets memory to zero or whether `posix_memalign` returns EINVAL when given bad alignment etc.

Tests are written in [minunit](https://github.com/siu/minunit), a "minimal unit testing framework for C". Running them is as simple as:
```bash
make test
```