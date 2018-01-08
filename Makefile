CC = clang
CFLAGS = -std=gnu11 -Wall -Wextra -g

all: build build/malloc.so build/standards

build:
	mkdir -p build

build/malloc.so: src/malloc.c src/malloc.h
	$(CC) $(CFLAGS) src/malloc.c -o build/malloc.so -fPIC -shared

build/standards: test/standards.c src/malloc.c src/malloc.h
	$(CC) $(CFLAGS) test/standards.c src/malloc.c -o build/standards -lrt -lm

test: all
	./build/standards

clean:
	rm -rf build