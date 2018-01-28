## Fork Guard Makefile

CC = clang
CFLAGS = -Wall
DEBUG_FLAGS = -DDEBUG -ggdb
LIBRARY = -fPIC -shared -ldl -lpthread

all: library test

library: clean
	mkdir -p build/
	$(CC) $(CFLAGS) $(LIBRARY) fork_guard.c vector.c -o build/fork_guard.so

library_debug: clean
	mkdir -p build/
	$(CC) $(CFLAGS) $(LIBRARY) $(DEBUG_FLAGS) fork_guard.c vector.c -o build/fork_guard.so

## Build the unit tests
test: clean library
	mkdir -p build/
	$(CC) $(CFLAGS) $(UNIT_TEST) $(INCLUDE_DIR) fork_guard_test.c vector.c -o build/fork_guard_test -lpthread

## Build the unit tests
debug_test: clean library_debug
	mkdir -p build/
	$(CC) $(CFLAGS) $(UNIT_TEST) $(INCLUDE_DIR) $(DEBUG_FLAGS) fork_guard_test.c vector.c -o build/fork_guard_test -lpthread

vector_test:
	mkdir -p build/
	$(CC) $(CFLAGS) -o build/vector_test vector.c -DVECTOR_UNIT_TEST=1

clean:
	rm -rf build/