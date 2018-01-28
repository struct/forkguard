## Make the unittest
make debug_test &&

## Run the test
FG_TRACING_MODE=1 FG_WHITELIST=example_symbol_lists/example_symbol_whitelist LD_PRELOAD=build/fork_guard.so build/fork_guard_test
