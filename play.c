#include <stdio.h>
#include "src/malloc.h"

#define LONG_DASH_LINE "--------------------------------------------------------------------------"

int main() {
    int *ptr = foo_malloc(1);
    fprintf(stderr, "foo_malloc(1) returned %p\n", ptr);
    mdump();

    fprintf(stderr, LONG_DASH_LINE "\n");

    *ptr = foo_malloc(1);
    fprintf(stderr, "foo_malloc(1) returned %p\n", ptr);
    mdump();

    return 0;
}