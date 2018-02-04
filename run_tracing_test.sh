## Make the unittest
cd src/ &&
make debug_test &&
cd ../ &&

## Run the test
FG_DUMPSTATS=1 FG_TRACING_MODE=1 FG_WHITELIST=whitelist_examples/example_symbol_whitelist LD_PRELOAD=build/fork_guard.so build/fork_guard_test
