/* Reference implementation of fork guard.
 * Copyright Chris Rohlf - 2017 */

#include "fork_guard.h"

/* The constructor handles most of the work when using
 * Fork Guard with LD_PRELOAD. Configuring Fork Guard
 * in this way is a matter of setting ENV variables.
 * Check out the README for more information on these */
__attribute__((constructor)) void fg_ctor() {
	LOG("Loading Fork Guard");
	/* Copy a pointer to the original fork() in libc */
	g_original_fork = dlsym(RTLD_NEXT, "fork");

	/* We parse symbols the first time fork is called */
	g_symbols_parsed = false;

	/* We parse the whitelist the first time fork is called */
	g_whitelist_parsed = false;

	/* We only want to dump page stats once */
	g_stats_dumped = false;

	/* The base load address of the main executable */
	g_exe_load_address = 0;

	/* Call into the linker to set g_exe_load_address */
	dl_iterate_phdr(get_exe_load_address, NULL);

	/* Initialize the symbol vectors */
	vector_init(&function_whitelist);
	vector_init(&all_pages);
	vector_init(&tracer_threads);

	FILE *fd = fopen("/proc/self/cmdline", "r");
	fgets((char *) program_name, sizeof(program_name), fd);
	fclose(fd);
	LOG("Program name is [%s]", program_name);
}

static int32_t get_exe_load_address(struct dl_phdr_info *info, size_t size, void *data) {
	if(strlen(info->dlpi_name) == 0) {
		LOG("Setting executable load address to %lx [%s]", info->dlpi_addr, info->dlpi_name);
		g_exe_load_address = info->dlpi_addr;
		return ERROR;
	}

	return OK;
}

/* Using a dtor in Fork Guard introduces some annoying
 * gotchas. Mainly that a forked child process will
 * eventually invoke it before it exits */
__attribute__((destructor)) void fg_dtor() {
	free_fg_vectors();
}

int32_t env_to_int(char *string) {
	char *p = getenv(string);

	if(p == NULL) {
		return 0;
	}

	return strtoul(p, NULL, 0);
}

/* Uses madvise to instruct the kernel
 * to drop a page upon fork of a child */
int32_t advise_page_on_fork(uintptr_t page, bool enforce) {
	int ret = 0;

	/* Make sure we are working the base page */
	uintptr_t p = get_base_page(page);

	/* This should be configurable for newer kernels */
	if(enforce == true) {
		ret = madvise((void *) p, getpagesize(), MADV_DONTFORK);
	} else {
		ret = madvise((void *) p, getpagesize(), MADV_DOFORK);
	}

	if(ret == ERROR) {
		LOG_ERROR("madvise failed");
		return ERROR;
	} else {
		return OK;
	}
}

/* These are just for debugging */
uint32_t total_pages = 0;
uint32_t pages_whitelisted = 0;

void *page_stats(void *p, void *data) {
	total_pages++;
	page_desc_t *page = (page_desc_t *) p;

	if(page->contains_wls) {
		pages_whitelisted++;
	}

	return NULL;
}

void *drop_pages(void *p, void *data) {
	int32_t ret = 0;
	page_desc_t *page = (page_desc_t *) p;

	if(page != NULL && page->contains_wls == false) {
		ret = advise_page_on_fork(page->page, true);

		if(ret == OK) {
			LOG("Dropping page 0x%lx in library [%s]", page->page, page->library);
		} else {
			LOG_ERROR("Failed to drop page %lx in library [%s]", page->page, page->library);
		}
	} else {
		LOG("Can't drop page 0x%lx [%s]", page->page, page->library);
	}

	return NULL;
}

void *add_whitelist_to_pages(void *p, void *data) {
	symbol_entry_t *sd = (symbol_entry_t *) p;

	/* Anything with a real symbol is handled in fork_guard_phdr_callback */
	if(sd->has_real_symbol == true) {
		return NULL;
	}

	/* Add this symbol to the proper page vector */
	page_desc_t *page_desc = NULL;
	page_desc = vector_for_each(&all_pages, (vector_for_each_callback_t *) find_existing_page, (void *) get_base_page(sd->addr));

	/* If we have seen this page before then
	 * add the symbol to the existing entry */
	if(page_desc == NULL) {
		page_desc = (page_desc_t *) malloc(sizeof(page_desc_t));
		page_desc->page = get_base_page(sd->addr);
		page_desc->dropped = false;
		page_desc->contains_wls = true;
		strncpy(page_desc->library, "unknown", sizeof(page_desc->library));
		vector_init(&page_desc->symbols);
		sd->ref_count++;
		vector_push(&page_desc->symbols, sd);
		vector_push(&all_pages, page_desc);
	} else {
		page_desc->contains_wls = true;
		sd->ref_count++;
		vector_push(&page_desc->symbols, sd);
	}

	return NULL;
}

/* Overload the fork function in libc */
pid_t fork(void) {
	pid_t child_pid;
	char *fg_whitelist = getenv(FG_WHITELIST);

	/* We only want to parse the symtab on disk once */
	if(getenv(FG_PARSE_EXE_SYMS) && vector_used(&symtab_functions) == 0) {
		parse_file_symtab(getenv(FG_PARSE_EXE_SYMS));
	}

	/* Handle the whitelist. We do this at the time of fork
	 * because it guarantees all libraries have been loaded */
	if(fg_whitelist != NULL && g_whitelist_parsed == false) {
		read_symbol_list(fg_whitelist);
		g_whitelist_parsed = true;
	}

	/* TODO - Use 'ret' */
	int32_t ret = 0;

	/* Gather symbols if we haven't yet. We only do this
	 * once. TODO: This should be configurable */
	if(g_symbols_parsed == false) {
		dl_iterate_phdr(fork_guard_phdr_callback, NULL);
		g_symbols_parsed = true;
	}

	/* We previously parsed a whitelist of symbols that we
	 * don't want to drop pages for. Even though we checked
	 * all symbols in the dl_iterate_phdr callback against
	 * this list we want to support adding offsets into
	 * libraries and those won't have symbols we can match
	 * against. To support that we invoke this callback
	 * which will iterate through the whitelist again and
	 * make sure all pages are marked correctly. */
	vector_for_each(&function_whitelist, (vector_for_each_callback_t *) add_whitelist_to_pages, NULL);

	vector_for_each(&all_pages, (vector_for_each_callback_t *) drop_pages, NULL);

	if(getenv(FG_DUMPSTATS) && g_stats_dumped == false) {
		g_stats_dumped = true;
		total_pages = 0;
		pages_whitelisted = 0;
		vector_for_each(&all_pages, (vector_for_each_callback_t *) page_stats, NULL);
		LOG("Pages Found: %d", total_pages);
		LOG("Pages Dropped: %d", pages_whitelisted);
		LOG("%.2f%% of pages were dropped", (float)pages_whitelisted / total_pages * 100.0);
	}

	// TODO this if conditional can be reduced
	// to a single block by checking internally
	// for tracing mode
	if(env_to_int(FG_TRACING_MODE) != 0) {
		LOG("Forking with tracing mode enabled");
		child_pid = g_original_fork();

		/* Allow the forked child process to happen, but
		 * monitor its execution. During this tracing we
		 * learn what code we can remove */
		if(child_pid != 0) {
			ret = child_fork_trace(child_pid);
			return child_pid;
		}

		return child_pid;
	} else {
		LOG("Forking with tracing mode disabled");
		child_pid = g_original_fork();

		/* If this is the parent process return the child pid */
		if(child_pid != 0) {
			return child_pid;
		}

		return child_pid;
	}
}

/* Assumes p is always allocated by malloc */
void vector_pointer_free(void *p) {
	free(p);
}

/* Some vectors (function_whitelist, all_pages) each hold
 * the same symbol_entry_t pointers. We don't want to free
 * them twice so we manage their lifetime with ref count */
void vector_symbol_free(void *p) {
	symbol_entry_t *se = (symbol_entry_t *) p;
	se->ref_count--;

	if(se->ref_count < 0) {
		free(se);
	}
}

void vector_free_internal(void *p) {
	page_desc_t *page = (page_desc_t *) p;
	vector_delete_all(&page->symbols, (vector_delete_callback_t *) vector_symbol_free);
	vector_free(&page->symbols);
	free(p);
}

/* Free some vectors we allocated earlier */
void free_fg_vectors() {
	vector_delete_all(&function_whitelist, (vector_delete_callback_t *) vector_symbol_free);
	vector_free(&function_whitelist);

	vector_delete_all(&all_pages, (vector_delete_callback_t *) vector_free_internal);
	vector_free(&all_pages);

	vector_delete_all(&tracer_threads, (vector_delete_callback_t *) vector_pointer_free);
	vector_free(&tracer_threads);
}

void *child_tracer(void *data) {
	tracer_thread_ctx_t *tctx = (tracer_thread_ctx_t *) data;
	pid_t child_pid = tctx->child_pid;
	pid_t cr;

	int32_t status = 0;
	int32_t ret = 0;

	struct user_regs_struct registers;

	/* Attach to the child process */
	ret = ptrace(PTRACE_ATTACH, child_pid, 0, 0);

	if(ret == ERROR) {
		LOG_ERROR("Failed to ptrace child PID %d", child_pid);
		return NULL;
	}

	do {
		/* Wait on the child process */
		cr = waitpid(child_pid, &status, 0);

		if(cr == ERROR) {
			LOG_ERROR("Failed to wait on child, attempting to kill it");
			ptrace(PTRACE_DETACH, child_pid, 0, 0);
			kill(child_pid, 9);
			return NULL;
		}

		if(WIFEXITED(status)) {
		    LOG("Child exited with status %d", WEXITSTATUS(status));
		    return NULL;
		} else if(WIFSIGNALED(status)) {
		    LOG("Child killed: %s %d", strsignal(WTERMSIG(status)), WTERMSIG(status));
		} else if(WIFSTOPPED(status)) {
		    LOG("Child stopped: %s %d", strsignal(WSTOPSIG(status)), WSTOPSIG(status));

		    switch(WSTOPSIG(status)) {
				case SIGSEGV:
				case SIGILL:
					ptrace(PTRACE_GETREGS, child_pid, NULL, &registers);
#ifdef __x86_64__
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.rip);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.rbp);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.rsp);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.rsi);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.rax);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.rbx);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.rcx);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.rdx);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.rdi);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.r8);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.r9);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.r10);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.r11);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.r12);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.r13);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.r14);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.r15);
#elif defined __i386__
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.eip);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.ebp);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.esp);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.esi);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.eax);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.ebx);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.ecx);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.edx);
					vector_for_each(&all_pages, (vector_for_each_callback_t *)check_dropped_pages, (void *) registers.edi);
#endif
					ptrace(PTRACE_DETACH, child_pid, 0, 0);
					return NULL;
					break;
		    }
		} else if(WIFCONTINUED(status)) {
		    LOG("Child continued");
		}

		ptrace(PTRACE_CONT, child_pid, 0, 0);

	} while(!WIFEXITED(status) && !WIFSIGNALED(status));

	return NULL;
}

/* Used by the parent in tracing mode to check
 * our list of known dropped pages for a crash
 * address. If found it creates a new entry in
 * the symbol whitelist, & reverses the behavior
 * of fork via madvise */
void *check_dropped_pages(void *p, void *data) {
	uintptr_t ip = (uintptr_t) data;
	int ret = 0;
	page_desc_t *page = (page_desc_t *) p;
	Dl_info dlinfo;

	uintptr_t ip_page = get_base_page(ip);

	if(page->page == ip_page) {
		ret = dladdr((void *) ip, &dlinfo);

		if(ret != 0) {
			if(page->dropped == false) {
				/* Its possible this function straddles two pages */
				LOG("Child IP 0x%lx [%s] [%s], in page 0x%lx was NOT dropped?!", ip, (char *) dlinfo.dli_sname, (char *)dlinfo.dli_fname, page->page);
			} else {
				LOG("Child IP 0x%lx [%s] [%s], which was dropped in page 0x%lx", ip, (char *) dlinfo.dli_sname, (char *)dlinfo.dli_fname, page->page);
			}

			page->contains_wls = true;

			/* Reverse the mapping behavior on fork via madvise */
			advise_page_on_fork(page->page, false);

			/* Create a new entry in the symbol whitelist vector */
			symbol_entry_t *se = (symbol_entry_t *) malloc(sizeof(symbol_entry_t));
			se->addr = ip;
			se->base_addr = ip_page;
			se->value = 0x0;
			se->size = 0;
			se->whitelist = true;

			/* We don't bother looking up a symbol here because
			 * the linker may return a symbol name that is close
			 * to the address but not exact. This will cause
			 * problems later when we go to use the whitelist */
			char sym_buf[32];
			snprintf(sym_buf, sizeof(sym_buf), "0x%lx", (uintptr_t) se->addr - (uintptr_t) dlinfo.dli_fbase);
			strncpy(se->name, sym_buf, sizeof(se->name));

			se->ref_count++;
			vector_push(&function_whitelist, se);

			/* Append the offset to the whitelist file if there is one */
			int32_t aret = append_symbol_list(getenv(FG_WHITELIST), page->library, se->name);

			if(aret == ERROR) {
				LOG_ERROR("Failed to append library to whitelist");
			}

			return page;
		} else {
			LOG("Unknown crash for IP 0x%lx in page 0x%lx", ip, page->page);
			return page;
		}
	}

	return NULL;
}

/* Fork Guard can be configured to spawn a thread
 * that monitors the child process. If it crashes
 * in any of the areas of memory previously removed
 * this will be logged */
int32_t child_fork_trace(pid_t child_pid) {
	int32_t ret = 0;

	tracer_thread_ctx_t *tracer_thread_ctx = (tracer_thread_ctx_t *) malloc(sizeof(tracer_thread_ctx_t));
	tracer_thread_ctx->child_pid = child_pid;

	vector_push(&tracer_threads, tracer_thread_ctx);

	/* Spawn a thread that will trace the child process */
	ret = pthread_create(&tracer_thread_ctx->ctx, NULL, &child_tracer, (void *) tracer_thread_ctx);

	ret = pthread_join(tracer_thread_ctx->ctx, NULL);

	return ret;
}

void *is_function_whitelisted(void *p, void *data) {
	symbol_entry_t *sym = (symbol_entry_t *) p;

	if(sym->addr == (uintptr_t) data && sym->whitelist == true) {
		LOG("found whitelist entry [%s] 0x%lx", sym->name, sym->addr);
		return sym;
	}

	return NULL;
}

/* Search the all_pages for an entry */
void *find_existing_page(void *p, void *data) {
	uintptr_t search_page = (uintptr_t) data;
	page_desc_t *page = (page_desc_t *) p;

	if(page->page == search_page) {
		return page;
	}

	return NULL;
}

/* Takes a symbol by symbol_entry_t and first checks it against the
 * function whitelist. If its not found then the symbol is added to
 * the appropriate page_desc_t entry */
int32_t handle_symbol(uintptr_t addr, symbol_entry_t *sd, const char *lib_name) {
	/* We previously built a symbol whitelist. This
	 * is where we check that list to see if it has
	 * the symbol we just found. If it does we mark
	 * this symbol entry as whitelisted */
	if((vector_for_each(&function_whitelist, (vector_for_each_callback_t *) is_function_whitelisted, 
			(void *) addr)) != NULL) {
		sd->whitelist = true;
	} else {
		sd->whitelist = false;
	}

	/* Add this symbol to the proper page vector */
	page_desc_t *page_desc = NULL;
	page_desc = vector_for_each(&all_pages, (vector_for_each_callback_t *) find_existing_page, (void *) get_base_page(sd->addr));

	/* If we have seen this page before then
	 * add the symbol to the existing entry */
	page_desc = add_symbol_to_page(page_desc, sd, lib_name);

	/* This function overlaps a page boundary, add
	 * the next page to the list as well */
	if(page_desc->page + getpagesize() < addr + sd->size) {
		page_desc_t *next_page = NULL;
		uintptr_t addr = sd->addr;
		sd->addr += getpagesize();
		next_page = vector_for_each(&all_pages, (vector_for_each_callback_t *) find_existing_page, (void *) get_base_page(sd->addr));
		next_page = add_symbol_to_page(next_page, sd, lib_name);
		sd->addr = addr;
	}

	return 0;
}

/* Invoked via dl_iterate_phdr for each loaded ELF object */
static int32_t fork_guard_phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
	const char *lib_name = "unknown_object";

	if(info->dlpi_addr == 0) {
		return 0;
	}

	if(strlen(info->dlpi_name) != 0) {
		lib_name = info->dlpi_name;
	} else {
		/* This is a disgusting hack. When dlpi_name is empty
		 * the first time its our executable. Any other time
		 * its probably the vdso. Theres no supported way of
		 * knowing if we are looking at the vdso or not */
		if(info->dlpi_addr != g_exe_load_address) {
			return 0;
		}
	}

	uintptr_t load_address = info->dlpi_addr;

	/* The main executable may appear to be loaded at 0. We
	 * need to fix that up by iterating for the right PT_LOAD
	 * segment and adding the virtual address */
	if(!load_address) {
		for(uint32_t i = 0; i < info->dlpi_phnum; i++) {
			if(info->dlpi_phdr[i].p_type == PT_LOAD) {
				load_address += info->dlpi_phdr[i].p_vaddr;
				break;
			}
		}
	}

	LOG("Found mapped ELF [%s] @ 0x%lx", lib_name, load_address);

	ElfW(Phdr*) phdr = NULL;

	/* First iterate through the program heaers for the
	 * PT_DYNAMIC segment. We need it to find symbols */
	for(uint32_t i = 0; i < info->dlpi_phnum; i++) {
		if(info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
			phdr = (ElfW(Phdr*)) &info->dlpi_phdr[i];
			LOG("Found PT_DYNAMIC segment @ %p %lx", phdr, info->dlpi_phdr[i].p_vaddr);
			break;
		}
	}

	if(phdr == NULL) {
		LOG("Got a NULL PT_DYNAMIC segment");
		return 0;
	}

	ElfW(Dyn*) dyn = (ElfW(Dyn*))(phdr->p_vaddr + load_address);
	ElfW(Sym*) sym = NULL;
	ElfW(Word) symbol_count = 0;
	ElfW(Word*) dt_hash = NULL;
	ElfW(Word*) dt_gnu_hash = NULL;
	char *strtab = NULL;

	/* Iterate through the dynamic segment to get symbols */
	for(uint32_t i = 0; i < (phdr->p_filesz/sizeof(ElfW(Dyn))); i++) {
		if(dyn[i].d_tag == DT_HASH) {
			dt_hash = (ElfW(Word*)) dyn[i].d_un.d_ptr;

			if(dt_hash == NULL) {
				continue;
			}

			symbol_count = dt_hash[1];
			LOG("DT_HASH Number of symbols: %d", symbol_count);
		}

		if(dyn[i].d_tag == DT_GNU_HASH) {
			dt_gnu_hash = (ElfW(Word *)) dyn[i].d_un.d_ptr;
			const uint32_t nbuckets = dt_gnu_hash[0];
			const uint32_t bloom_size = dt_gnu_hash[2];
			const uint64_t* bloom = (void*) &dt_gnu_hash[4];
			const uint32_t* buckets = (void*) &bloom[bloom_size];

			/* This is good enough to get the size of the dynsym but
			 * it won't tell us total number of symbols including the
			 * the symtab. If we want the symtab for the main exe we
			 * to parse it from disk */
			for(uint32_t index = 0; index < nbuckets; index++) {
				if(buckets[index] > symbol_count) {
					symbol_count = buckets[index];
				}
			}

			LOG("DT_GNU_HASH Number of symbols: %d", symbol_count);
		}

		if(dyn[i].d_tag == DT_SYMTAB) {
			sym = (ElfW(Sym*)) dyn[i].d_un.d_ptr;
		}

		if(dyn[i].d_tag == DT_STRTAB) {
			strtab = (char *) dyn[i].d_un.d_ptr;
		}
	}

	if(symbol_count == 0 || sym == NULL || strtab == NULL) {
		LOG_ERROR("Cannot parse the symbol table");
		return 0;
	}

	LOG("Found symbol table @ %p, number of symbols %d", sym, symbol_count);

	for(int i = 0; i < symbol_count; i++, sym++) {
		uintptr_t addr = load_address + sym->st_value;
		/* We only care about symbols of type STT_FUNC because
		 * they likely point at executable code pages. Functions
		 * with a size of 0 likely imported */
		if((sym->st_info & 0xf) != STT_FUNC || sym->st_size == 0) {
			continue;
		}

		LOG("Symbol value base addr = 0x%lx [%s][%d]: 0x%lx -> 0x%lx [%s]", get_base_page(addr), lib_name, i,
			sym->st_value, load_address + sym->st_value, &strtab[sym->st_name]);

		symbol_entry_t *sd = (symbol_entry_t *) malloc(sizeof(symbol_entry_t));
		memset(sd, 0x0, sizeof(symbol_entry_t));
		sd->addr = addr;
		sd->base_addr = load_address;
		sd->value = sym->st_value;
		sd->size = sym->st_size;
		memcpy(sd->name, &strtab[sym->st_name], strlen(&strtab[sym->st_name]));

		handle_symbol(addr, sd, lib_name);
	}

	return OK;
}

void *add_symbol_to_page(page_desc_t *page_desc, symbol_entry_t *sd, const char *lib_name) {
	if(page_desc == NULL) {
		page_desc = (page_desc_t *) malloc(sizeof(page_desc_t));
		page_desc->page = get_base_page(sd->addr);
		page_desc->dropped = false;
		page_desc->contains_wls = sd->whitelist;

		if(lib_name != NULL) {
			strncpy(page_desc->library, lib_name, sizeof(page_desc->library));
		}

		vector_init(&page_desc->symbols);
		sd->ref_count++;
		vector_push(&page_desc->symbols, sd);
		vector_push(&all_pages, page_desc);
	} else {
		page_desc->contains_wls = sd->whitelist;
		sd->ref_count++;
		vector_push(&page_desc->symbols, sd);
	}

	return page_desc;
}

/* TODO - This function is called by a thread and is not
 * thread safe. We need a mutex to guard against file
 * writes here. */
int32_t append_symbol_list(char *symbol_file, char *library, char *symbol) {
	pthread_mutex_lock(&whitelist_lock);

	if(symbol_file == NULL || symbol == NULL) {
		LOG_ERROR("Symbol list is NULL");
		return ERROR;
	}

	/* TODO - check the path is legit first. Better error handling etc */
	FILE *fd = fopen(symbol_file, "a");

	if(fd == NULL) {
		LOG_ERROR("Failed to open file %s", symbol_file);
		pthread_mutex_unlock(&whitelist_lock);
		return ERROR;		
	}

	LOG("Appending to whitelist: [%s:%s]", library, symbol);

	fprintf(fd, "\n# Added by Fork Guard tracing mode\n%s:%s\n", library, symbol);
	fflush(fd);
	fclose(fd);

	pthread_mutex_unlock(&whitelist_lock);
	return OK;
}

/* Invoked by read_symbol_list. Used for when the whitelist
 * passes in an offset to a library. We need to know that
 * library base address and this is how we get it */
static int32_t build_whitelist_callback(struct dl_phdr_info *info, size_t size, void *data) {
	symbol_entry_t *sd = (symbol_entry_t *) data;

	if(data == NULL) {
		LOG_ERROR("Passed a NULL symbol value")
		return ERROR;
	}

	/* We need to handle offsets into the main program.
	 * This is done by comparing what was specified in
	 * the symbol whitelist with program_name. If they
	 * match and this mapping has no dlpi_name then its
	 * probably our main exe mapping. */
	if(strcmp((char *) sd->base_addr, info->dlpi_name) == 0 ||
		((strlen(info->dlpi_name) == 0) && strcmp((char *) sd->base_addr, program_name) == 0)) {
		sd->base_addr = info->dlpi_addr;
		sd->addr += sd->base_addr;
		return OK;
	}

	return OK;
}

void *each_symtab(void *p, void *data) {
	char *name = (char *) data;
	symbol_entry_t *sd = (symbol_entry_t *) p;

	if(strcmp(sd->name, name) == 0) {
		return sd;
	}

	return NULL;
}

/* Takes a newline seperated file of symbols and builds
 * a temporary vector for symbol parsing to use later.
 * The whitelist format is simple:
 	- <library path>:symbol
	- <library path>:<offset>
 */
int32_t read_symbol_list(char *symbol_file) {
	char line[512];
	char library_path[512];
	char *library_handle = NULL;
	char *p = NULL;
	int32_t ret = 0;

	/* TODO - check the path is legit first. Better error handling etc */
	FILE *fd = fopen(symbol_file, "r+");

	if(symbol_file == NULL) {
		LOG_ERROR("Symbol list is NULL");
		return ERROR;
	}

	if(fd == NULL) {
		LOG_ERROR("Failed to open file %s", symbol_file);
		return ERROR;
	}

	memset(line, 0x0, sizeof(line));
	memset(library_path, 0x0, sizeof(library_path));

    while(fgets(line, sizeof(line), fd)) {
    	/* Ignore newlines and comments */
    	if(line[0] == '\n' || line[0] == '#') {
    		continue;
    	}

    	line[strlen(line)-1] = '\0';
		p = strtok(line, ":");

		if(p == NULL) {
			LOG("Improperly formatted whitelist line [%s]", line);
			continue;
		}

    	if(library_handle == NULL || strcmp(p, library_path) != 0) {
    		if(library_handle != NULL) {
				dlclose(library_handle);
			}

			/* Passing NULL to dlopen returns a handle to the main program */
			if(getenv(FG_PARSE_EXE_SYMS) && strcmp(library_path, getenv(FG_PARSE_EXE_SYMS)) == 0) {
				library_handle = dlopen(NULL, RTLD_NOW);
			} else {
				library_handle = dlopen(p, RTLD_NOW);
			}

    		if(library_handle == NULL) {
    			LOG("Failed to get handle for library %s", p);
    			continue;
    		}

    		strncpy(library_path, p, sizeof(library_path));
    		LOG("Looking for symbols in library: %s", p);
		}

		p = strtok(NULL, ":");

		if(p == NULL) {
			LOG("Improperly formatted whitelist line [%s]", line);
			continue;
		}

		/* We can't create the entire structure
		 * because all we have is an address. */
		symbol_entry_t *sd = (symbol_entry_t *) malloc(sizeof(symbol_entry_t));
		memset(sd, 0x0, sizeof(symbol_entry_t));

		/* Safe to assume an offset is being supplied */
		if(strncmp(p, "0x", 2) == 0) {
			sd->addr = (uintptr_t) strtoul(p, NULL, 16);

			/* base_addr is set to library path because we use
			 * it in a strncmp in build_whitelist_callback */
			sd->base_addr = (uintptr_t) library_path;
			ret = dl_iterate_phdr(build_whitelist_callback, (void *) sd);

			if(ret == ERROR) {
				LOG("Could not locate library base address for [%s]", library_path);
				free(sd);
				continue;
			}

			sd->has_real_symbol = false;

			LOG("Successfully found offset [%s] in library [%s]:[0x%lx] @ 0x%lx", p, library_path, sd->base_addr, sd->addr);
		} else {
			if(getenv(FG_PARSE_EXE_SYMS) && strcmp(library_path, getenv(FG_PARSE_EXE_SYMS)) == 0) {
				/* The symbol is in the main executable. Use the stored
				 * list of symbols from the symtab instead of dlsym */
				symbol_entry_t *se = vector_for_each(&symtab_functions, (vector_for_each_callback_t *) &each_symtab, p);

				if(se != NULL) {
					symbol_entry_copy(sd, se);
				}
			} else {
				sd->addr = (uintptr_t) dlsym(library_handle, p);

				if(!sd->addr) {
					LOG("Could not locate symbol [%s]", p);
					free(sd);
					continue;
				}

			}

			Dl_info dlinfo;

			if(dladdr((void *) sd->addr, &dlinfo) > 0) {
				sd->base_addr = (uintptr_t) dlinfo.dli_fbase;
			} else {
				LOG("Could not locate library base address with dladdr [%s]", p);
				free(sd);
				continue;
			}

			sd->has_real_symbol = true;
			LOG("Successfully found symbol [%s] in library [%s]:[0x%lx] @ 0x%lx", p, library_path, sd->base_addr, sd->addr);
		}

		sd->whitelist = true;
		strncpy(sd->name, p, sizeof(sd->name));

		sd->ref_count++;
		vector_push(&function_whitelist, sd);
	}

	if(library_handle != NULL) {
		dlclose(library_handle);
	}

	fclose(fd);

	return OK;
}

/* Deep copies a symbol_entry_t */
void symbol_entry_copy(symbol_entry_t *to, symbol_entry_t *from) {
	to->addr = from->addr;
	to->base_addr = from->base_addr;
	to->value = from->value;
	to->size = from->size;
	to->whitelist = from->whitelist;
	to->has_real_symbol = from->has_real_symbol;
	memcpy(to->name, from->name, sizeof(to->name));
}

uintptr_t get_base_page(uintptr_t addr) {
	uintptr_t page_size = getpagesize();
	return (addr & ~(page_size-1));
}

/* Parses the symtab of an ELF file on disk and
 * adds the symbols to the vector */
int32_t parse_file_symtab(const char *path) {
	int fd = open(path, O_RDONLY);

	if(fd == ERROR) {
		LOG("Could not open [%s]", path);
		return ERROR;
	}

	struct stat sb;
	fstat(fd, &sb);

	uintptr_t elf_mem = (uintptr_t) mmap(0, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	if(elf_mem == ERROR) {
		LOG("Could not mmap [%s]", path);
		close(fd);
		return ERROR;
	}

	ElfW(Ehdr*) elf_header = (ElfW(Ehdr*)) elf_mem;

	if(elf_header->e_ident[EI_MAG0] != 0x7F && elf_header->e_ident[EI_MAG1] != 'E' && 
			elf_header->e_ident[EI_MAG2] != 'L' && elf_header->e_ident[EI_MAG3] != 'F') {
		LOG("%s is not an ELF file", path);
		munmap(elf_header, sb.st_size);
		close(fd);
		return ERROR;
	}

	ElfW(Shdr *) shdr = (ElfW(Shdr *)) (elf_mem + elf_header->e_shoff);
	ElfW(Shdr *) symtab = NULL;
	char *shdr_strtab = NULL;
	char *strtab = NULL;

	for(uint32_t i = 0; i < elf_header->e_shnum; i++, shdr++) {
		if(shdr->sh_type == SHT_SYMTAB) {
			symtab = shdr;
		}

		if(i == elf_header->e_shstrndx) {
			shdr_strtab = (char *)(elf_mem + shdr->sh_offset);
		}
	}

	if(shdr_strtab == NULL) {
		LOG("Could not find section header strtab");
		munmap(elf_header, sb.st_size);
		close(fd);
		return ERROR;
	}

	shdr = (ElfW(Shdr *)) (elf_mem + elf_header->e_shoff);

	/* Iterate the section headers one more time to get
	 * the symtab now that we know the shdr strtab */
	for(uint32_t i = 0; i < elf_header->e_shnum; i++, shdr++) {
		if(shdr->sh_type == SHT_STRTAB && i != elf_header->e_shstrndx &&
				(strcmp(&shdr_strtab[shdr->sh_name], ".strtab") == 0)) {
			strtab = (char *)(elf_mem + shdr->sh_offset);
		}
	}

	if(symtab == NULL || strtab == NULL) {
		LOG("Could not find a symtab");
		munmap(elf_header, sb.st_size);
		close(fd);
		return ERROR;
	}

	ElfW(Sym *) sym = (ElfW(Sym*)) (elf_mem + symtab->sh_offset);

	/* This is a little gross but its reliable because we have
	 * the section header on disk and not a segment in memory */
	uint32_t symbol_count = (symtab->sh_size / sizeof(ElfW(Sym)));

	for(uint32_t i = 0; i < symbol_count; i++, sym++) {
		if((sym->st_info & 0xf) != STT_FUNC || sym->st_size == 0) {
			continue;
		}

		uintptr_t addr = g_exe_load_address + sym->st_value;

		LOG("Symbol value base addr = 0x%lx [%s][%d]: 0x%lx -> 0x%lx [%s]", get_base_page(addr), path, i,
			sym->st_value, g_exe_load_address + sym->st_value, &strtab[sym->st_name]);

		symbol_entry_t *sd = (symbol_entry_t *) malloc(sizeof(symbol_entry_t));
		memset(sd, 0x0, sizeof(symbol_entry_t));
		sd->addr = addr;
		sd->base_addr = g_exe_load_address;
		sd->value = sym->st_value;
		sd->size = sym->st_size;
		memcpy(sd->name, &strtab[sym->st_name], strlen(&strtab[sym->st_name]));
		sd->ref_count++;
		vector_push(&symtab_functions, sd);
	}

	munmap(elf_header, sb.st_size);
	close(fd);

	return OK;
}
