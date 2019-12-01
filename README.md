# README

Fork Guard is a proof-of-concept C library that demonstrates an experimental exploit mitigation technique for programs designed to fork a child process that handles untrusted data. Fork Guard removes unused code from the virtual memory of the forked child process which reduces attack surface and unnecessary code that can be used for code reuse (ROP/BROP) payloads.

It works by inspecting the symbol tables of the process that loaded it and then using the madvise syscall to advise the kernel of which memory pages it should unmap or zeroize in the child process upon fork. Fork Guard is most useful in programs like server daemons that fork child processes to handle incoming requests (DNS, Caching proxies, HTTPD servers, etc).

## Technical Details

Fork Guard works by parsing out the ELF symbol table(s) of the process that loads, this includes the processes own executable (if `FG_PARSE_EXE_SYMS` is enabled) and every loaded shared library. These symbols are used to locate as much code loaded in memory as possible. This is done by using `dl_iterate_phdr` callbacks from the linker and parsing ELF structures in memory.

Before Fork Guard can be in enforcing mode it has to trace a child process with ptrace in order to know which pages of code it will need at runtime. These code whitelist files can be built manually by hand but its error prone. You can use `FG_TRACING_MODE` to build these files automatically and then safely run in enforcing mode.

## Configuration

Because of how Fork Guard is loaded with LD_PRELOAD it can only be configured by environment variables. These are documented below:

```
FG_TRACING_MODE - Trace all child processes with ptrace to build a code whitelist
FG_WHITELIST - A path to the whitelist file
FG_DUMPSTATS - Prints data collected to stdout
FG_PARSE_EXE_SYMS - Parse the code from the loaded executable, not just loaded shared libraries
```
