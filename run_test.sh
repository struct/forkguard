## Make the unittest
cd src/ &&
make test &&
cd ../ &&

FULL_PATH=`pwd`

## Run the test
FG_DUMPSTATS=1 FG_WHITELIST=whitelist_examples/example_symbol_whitelist FG_PARSE_EXE_SYMS=/home/user/shared/forkguard/build/fork_guard_test \
LD_PRELOAD=build/fork_guard.so $FULL_PATH/build/fork_guard_test 80
