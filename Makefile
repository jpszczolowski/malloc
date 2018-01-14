CC = clang
CFLAGS = -std=gnu11 -Wall -Wextra -fno-omit-frame-pointer -g -fsanitize=address

all: build build/malloc.so build/standards build/functional play

build:
	mkdir -p build

build/malloc.so: src/malloc.c src/malloc.h
	$(CC) $(CFLAGS) src/malloc.c -o build/malloc.so -fPIC -shared

build/standards: test/standards.c src/malloc.c src/malloc.h
	$(CC) $(CFLAGS) test/standards.c src/malloc.c -o build/standards -lrt -lm

build/functional: test/functional.c src/malloc.c src/malloc.h
	$(CC) $(CFLAGS) test/functional.c src/malloc.c -o build/functional -lrt -lm

play: src/malloc.h src/malloc.c play.c
	$(CC) $(CFLAGS) play.c src/malloc.c -o play

test: all
	./build/standards && ./build/functional

clean:
	rm -rf build play