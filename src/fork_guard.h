/* Reference implementation of fork guard.
 * Copyright Chris Rohlf - 2017-2019 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "vector_t/vector.h"

#define OK 0
#define ERROR -1

#define NO 0
#define YES 1

#define MAX_SYMBOL_NAME 512
#define MAX_LIBRARY_PATH 4096

/* Environment variables for controlling Fork Guard */
#define FG_WHITELIST "FG_WHITELIST"
#define FG_TRACING_MODE "FG_TRACING_MODE"
#define FG_DUMPSTATS "FG_DUMPSTATS"
#define FG_PARSE_EXE_SYMS "FG_PARSE_EXE_SYMS"

#if DEBUG
	#define LOG_ERROR(msg, ...)	\
		fprintf(stderr, "[LOG][%d](%s) (%s) - " msg "\n", getpid(), __FUNCTION__, strerror(errno), ##__VA_ARGS__); \
		fflush(stderr);

	#define LOG(msg, ...)	\
		fprintf(stdout, "[LOG][%d](%s) " msg "\n", getpid(), __FUNCTION__, ##__VA_ARGS__); \
		fflush(stdout);
#else
	#define LOG_ERROR(...)
	#define LOG(...)
#endif

/* Symbol entries are derived from user inputs such
 * as a whitelist. But Fork Guard works
 * by removing entire pages of memory. These data
 * structures are for abstracting away symbol data,
 * and page information which we use internally. */
typedef struct _symbol_entry_t {
	/* Absolute memory address (base_addr + value) */
	uintptr_t addr;
	/* Library base address */
	uintptr_t base_addr;
	/* st_value as extracted from ELF section in memory */
	uintptr_t value;
	/* st_size of the function */
	size_t size;
	/* Whitelist flag */
	bool whitelist;
	/* ASCII name of the symbol */
	char name[MAX_SYMBOL_NAME];
	/* true if by name, false if by offset */
	bool has_real_symbol;
	/* Reference count */
	int32_t ref_count;
} symbol_entry_t;

/* We store them seperately to speed up searching */
vector_t function_whitelist;

/* Stored symbols from on disk .symtab parsing */
vector_t symtab_functions;

bool g_symbols_parsed;
bool g_whitelist_parsed;
bool g_stats_dumped;

/* Internally Fork Guard works at the page level.
 * Before any pages are dropped we check what
 * symbols point at functions in that page as
 * they may be on the whitelist.
 * Fork Guard does not track if the page is a
 * contiguous mapping or not. We intentionally
 * poke holes in library mappings. */
typedef struct _page_desc_t {
	/* The base page address we are tracking */
	uintptr_t page;
	/* Was this page dropped? */
	bool dropped;
	/* What library occupies this mapping? */
	char library[MAX_LIBRARY_PATH];
	/* Contains a whitelisted symbol */
	bool contains_wls;
	/* What symbols represent functions on these
	 * pages. This is a vector of symbol_entry_t */
	vector_t symbols;
} page_desc_t;

/* Store information about each code page we find */
vector_t all_pages;

/* This stores information about which
 * thread is tracing which child process */
typedef struct _tracer_thread_ctx_t {
	pthread_t ctx;
	pid_t child_pid;
} tracer_thread_ctx_t;

vector_t tracer_threads;

/* Base address of the main exe */
uintptr_t g_exe_load_address;

pthread_mutex_t whitelist_lock;

const char program_name[1024];

uintptr_t get_base_page(uintptr_t addr);
int32_t env_to_int(char *string);
int32_t advise_page_on_fork(uintptr_t page, bool enforce);
int32_t read_symbol_list(char *symbol_file);
int32_t append_symbol_list(char *symbol_file, char *library, char *symbol);
int32_t child_fork_trace(pid_t child_pid);
int32_t handle_symbol(uintptr_t addr, symbol_entry_t *sd, const char *lib_name);
int32_t parse_file_symtab(const char *path);
void symbol_entry_copy(symbol_entry_t *to, symbol_entry_t *from);
void vector_pointer_free(void *p);
void vector_free_internal(void *p);
void free_fg_vectors();
void *add_symbol_to_page(page_desc_t *page_desc, symbol_entry_t *sd, const char *lib_name);
void *drop_pages(void *p, void *data);
void *page_stats(void *p, void *data);
void *add_whitelist_to_pages(void *p, void *data);
void *check_dropped_pages(void *p, void *data);
void *find_existing_page(void *p, void *data);
void *is_symbol_whitelisted(void *p, void *data);
void *each_symtab(void *p, void *data);
static int32_t get_exe_load_address(struct dl_phdr_info *info, size_t size, void *data);
static int32_t fork_guard_phdr_callback(struct dl_phdr_info *info, size_t size, void *data);
static int32_t build_whitelist_callback(struct dl_phdr_info *info, size_t size, void *data);

/* Overloaded libc functions */
pid_t(*g_original_fork)(void);
