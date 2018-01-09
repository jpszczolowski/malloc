#include <stdio.h>
#include "src/malloc.h"

int main() {
    int *ptr = foo_malloc(1);
    fprintf(stderr, "foo_malloc(1) returned %p\n", ptr);
    mdump();

    return 0;
}