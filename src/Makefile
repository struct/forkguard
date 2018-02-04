## Fork Guard Makefile

CC = clang
CFLAGS = -Wall
DEBUG_FLAGS = -DDEBUG -ggdb
LIBRARY = -fPIC -shared -ldl -lpthread
ASAN = -fsanitize=address

all: library test

## Build the library
library: clean
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(LIBRARY) fork_guard.c vector.c -o ../build/fork_guard.so

## Build a debug version of the library
library_debug: clean
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(LIBRARY) $(DEBUG_FLAGS) fork_guard.c vector.c -o ../build/fork_guard.so

## Build the unit test
test: clean library
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(UNIT_TEST) $(INCLUDE_DIR) fork_guard_test.c vector.c -o ../build/fork_guard_test -lpthread

## Build a debug version of the unit test
debug_test: clean library_debug
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(UNIT_TEST) $(INCLUDE_DIR) $(DEBUG_FLAGS) fork_guard_test.c vector.c -o ../build/fork_guard_test -lpthread

## Build the vector tests
vector_test:
	mkdir -p ../build/
	$(CC) $(ASAN) $(DEBUG_FLAGS) $(CFLAGS) -o ../build/vector_test vector.c -DVECTOR_UNIT_TEST=1

clean:
	rm -rf ../build/