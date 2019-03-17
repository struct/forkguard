## Make the unittest
cd src/ &&
make debug_test &&
cd ../ &&

FULL_PATH=`pwd`

## Run the test
FG_DUMPSTATS=1 FG_TRACING_MODE=1 FG_WHITELIST=whitelist_examples/example_symbol_whitelist \
FG_PARSE_EXE_SYMS=$FULL_PATH/build/fork_guard_test LD_PRELOAD=$FULL_PATH/build/fork_guard.so $FULL_PATH/build/fork_guard_test 80
