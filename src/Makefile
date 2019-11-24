## Fork Guard Makefile

CC = clang
CFLAGS = -Wall
EXE_CFLAGS = -fPIE -pie
DEBUG_FLAGS = -DDEBUG -ggdb
LIBRARY = -fPIC -shared -ldl -lpthread
ASAN = -fsanitize=address
SRCS = fork_guard.c vector_t/vector.c
TEST_SRCS = fork_guard_test.c vector_t/vector.c

all: library test

## Build the library
library: clean
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(LIBRARY) $(SRCS) -o ../build/fork_guard.so

## Build a debug version of the library
library_debug: clean
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(LIBRARY) $(DEBUG_FLAGS) $(SRCS) -o ../build/fork_guard.so

## Build the unit test
test: clean library
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(INCLUDE_DIR) $(TEST_SRCS) -o ../build/fork_guard_test -lpthread

## Build a debug version of the unit test
debug_test: clean library_debug
	mkdir -p ../build/
	$(CC) $(CFLAGS) $(EXE_CFLAGS) $(INCLUDE_DIR) $(DEBUG_FLAGS) $(TEST_SRCS) -o ../build/fork_guard_test -lpthread

clean:
	rm -rf ../build/