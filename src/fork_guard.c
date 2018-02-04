/* Reference implementation of fork guard.
 * Copyright Chris Rohlf - 2017 */

#include "fork_guard.h"

/* The constructor handles most of the work when using
 * Fork Guard with LD_PRELOAD. Configuring Fork Guard
 * in this way is a matter of setting ENV variables.
 * Check out the README for more information on these */
__attribute__((constructor)) void fg_ctor() {
	/* Copy a pointer to the original fork() in libc */
	original_fork = dlsym(RTLD_NEXT, "fork");

	/* We parse symbols the first time fork is called */
	symbols_parsed = false;

	/* We parse the whitelist the first time fork is called */
	whitelist_parsed = false;

	/* We only want to dump page stats once */
	stats_dumped = false;

	/* Initialize the symbol vectors */
	vector_init(&function_whitelist);
	vector_init(&all_pages);
	vector_init(&tracer_threads);
}

/* Uses madvise to instruct the kernel
 * to drop a page upon fork of a child */
int32_t drop_page_on_fork(uintptr_t page, bool enforce) {
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
		ret = drop_page_on_fork(page->page, true);

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
		vector_push(&page_desc->symbols, sd);
		vector_push(&all_pages, page_desc);
	} else {
		page_desc->contains_wls = true;
		vector_push(&page_desc->symbols, sd);
	}

	return NULL;
}

/* Overload the fork function in libc */
pid_t fork(void) {
	pid_t child_pid;
	char *fg_whitelist = getenv(FG_WHITELIST);
	char *fg_tracing_mode = getenv(FG_TRACING_MODE);

	/* Handle the whitelist */
	if(fg_whitelist != NULL && whitelist_parsed == false) {
		read_symbol_list(fg_whitelist);
		whitelist_parsed = true;
	}

	/* TODO - Use 'ret' */
	int32_t ret = 0;

	/* Gather symbols if we haven't yet. We only do this
	 * once. TOOD: This should be configurable */
	if(symbols_parsed == false) {
		dl_iterate_phdr(fork_guard_phdr_callback, NULL);
		symbols_parsed = true;
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

	if(getenv("FG_DUMPSTATS") && stats_dumped == false) {
		stats_dumped = true;
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
	if(fg_tracing_mode != NULL && strtoul(fg_tracing_mode, NULL, 0) != 0) {
		LOG("Forking with tracing mode enabled");
		child_pid = original_fork();

		/* Allow the forked child process to happen, but
		 * monitor its execution. During this tracing we
		 * learn what code we can remove */
		if(child_pid != 0) {
			ret = child_fork_trace(child_pid);
			return child_pid;
		}

		free_fg_vectors();
		return child_pid;
	} else {
		LOG("Forking with tracing mode disabled");
		child_pid = original_fork();

		/* If this is the parent process return the child pid */
		if(child_pid != 0) {
			return child_pid;
		}

		/* This is the child process */
		free_fg_vectors();
		return child_pid;
	}
}

/* Assumes p is always allocated by malloc */
void vector_pointer_free(void *p) {
	free(p);
}

void vector_free_internal(void *p) {
	/*page_desc_t *page = (page_desc_t *) p;
	vector_delete_all(&page->symbols, (vector_delete_callback_t *) vector_pointer_free);
	vector_free(&page->symbols);*/
	free(p);
}

/* Free some vectors we allocated earlier */
void free_fg_vectors() {
	vector_delete_all(&function_whitelist, (vector_delete_callback_t *) vector_pointer_free);
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
		    LOG("Child killed: %s", strsignal(WTERMSIG(status)));
		} else if(WIFSTOPPED(status)) {
		    LOG("Child stopped: %s", strsignal(WSTOPSIG(status)));

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
			LOG("Child IP 0x%lx [%s] [%s], which was dropped in page 0x%lx", ip, (char *) dlinfo.dli_sname, (char *)dlinfo.dli_fname, page->page);
			page->contains_wls = true;

			/* Reverse the mapping behavior on fork via madvise */
			drop_page_on_fork(page->page, false);

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

			vector_push(&function_whitelist, se);

			/* Append the offset to the whitelist file if there is one */
			int32_t aret = append_symbol_list(getenv("FG_WHITELIST"), page->library, se->name);

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

/* Invoked via dl_iterate_phdr for each loaded ELF object */
static int32_t fork_guard_phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
	if(strlen(info->dlpi_name) == 0) {
		return 0;
	}

	LOG("Found .so [%s] @ 0x%lx", info->dlpi_name, info->dlpi_addr);

	ElfW(Phdr*) phdr = NULL;

	/* First iterate through the program heaers for the
	 * PT_DYNAMIC segment. We need it to find symbols */
	for(int i = 0; i < info->dlpi_phnum; i++) {
		if(info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
			phdr = (ElfW(Phdr*)) &info->dlpi_phdr[i];
			LOG("Found PT_DYNAMIC segment @ %p", phdr);
			break;
		}
	}

	ElfW(Dyn*) dyn = (ElfW(Dyn*)) (phdr->p_vaddr + info->dlpi_addr);
	ElfW(Sym*) sym = NULL;
	ElfW(Word) symbol_count = 0;
	ElfW(Word*) dt_hash = NULL;
	char *strtab = NULL;

	/* Iterate through the dynamic segment to get symbols */
	for(int i=0; i < (phdr->p_filesz/sizeof(ElfW(Dyn))); i++) {
		if(dyn[i].d_tag == DT_HASH) {
			dt_hash = (ElfW(Word*)) dyn[i].d_un.d_ptr;
			symbol_count = dt_hash[1];
			LOG("Number of symbols: %d", symbol_count);
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

	//LOG("Found symbol table @ %p, number of symbols %d", sym, symbol_count);

	for(int i=0; i < symbol_count; i++) {
		uintptr_t addr = info->dlpi_addr+sym->st_value;

		/* We only care about symbols of type STT_FUNC because
		 * they likely point at executable code pages. Functions
		 * with a size of 0 are likely imports */
		if((sym->st_info & 0xf) != STT_FUNC || sym->st_size == 0) {
			sym++;
			continue;
		}

		LOG("Symbol value base addr = 0x%lx [%s][%d]: 0x%lx -> 0x%lx [%s]", get_base_page(addr), info->dlpi_name, i,
			sym->st_value, info->dlpi_addr+sym->st_value, &strtab[sym->st_name]);

		symbol_entry_t *sd = (symbol_entry_t *) malloc(sizeof(symbol_entry_t));
		memset(sd, 0x0, sizeof(symbol_entry_t));
		sd->addr = addr;
		sd->base_addr = info->dlpi_addr;
		sd->value = sym->st_value;
		sd->size = sym->st_size;
		memcpy(sd->name, &strtab[sym->st_name], strlen(&strtab[sym->st_name]));

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
		page_desc = vector_for_each(&all_pages, (vector_for_each_callback_t *) find_existing_page, (void *) get_base_page(addr));

		/* If we have seen this page before then
		 * add the symbol to the existing entry */
		if(page_desc == NULL) {
			page_desc = (page_desc_t *) malloc(sizeof(page_desc_t));
			page_desc->page = get_base_page(addr);
			page_desc->dropped = false;
			page_desc->contains_wls = sd->whitelist;
			strncpy(page_desc->library, info->dlpi_name, sizeof(page_desc->library));
			vector_init(&page_desc->symbols);
			vector_push(&page_desc->symbols, sd);
			vector_push(&all_pages, page_desc);
		} else {
			page_desc->contains_wls = sd->whitelist;
			vector_push(&page_desc->symbols, sd);
		}

		sym++;
	}

	return OK;
}

int32_t append_symbol_list(char *symbol_file, char *library, char *symbol) {
	if(symbol_file == NULL || symbol == NULL) {
		LOG_ERROR("Symbol list is NULL");
		return ERROR;
	}

	/* TODO - check the path is legit first. Better error handling etc */
	FILE *fd = fopen(symbol_file, "a");

	if(fd == NULL) {
		LOG_ERROR("Failed to open file %s", symbol_file);
		return ERROR;		
	}

	LOG("Appending to whitelist: [%s:%s]", library, symbol);

	fprintf(fd, "\n# Added by Fork Guard tracing mode\n%s:%s\n", library, symbol);
	fflush(fd);
	fclose(fd);

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

	if(strcmp((char *) sd->base_addr, info->dlpi_name) == 0) {
		sd->base_addr = info->dlpi_addr;
		sd->addr += sd->base_addr;
		return 0;
	}

	return OK;
}

/* Takes a newline seperated file of symbols and builds
 * a temporary vector for symbol parsing to use later .
 * The whitelist format is simple:
 	- <library path>:symbol
	- <library path>:<offset>
 */
int32_t read_symbol_list(char *symbol_file) {
	if(symbol_file == NULL) {
		LOG_ERROR("Symbol list is NULL");
		return ERROR;
	}

	/* TODO - check the path is legit first. Better error handling etc */
	FILE *fd = fopen(symbol_file, "r+");

	if(fd == NULL) {
		LOG_ERROR("Failed to open file %s", symbol_file);
		return ERROR;
	}

	char line[512];
	char library_path[512];
	char *library_handle = NULL;
	char *p = NULL;
	int32_t ret = 0;

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

			library_handle = dlopen(p, RTLD_NOW);

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

			LOG("Successfully found address [%s] in library [0x%lx] @ 0x%lx", p, sd->base_addr, sd->addr);
		} else {
			sd->addr = (uintptr_t) dlsym(library_handle, p);

			if(sd->addr == 0x0) {
				LOG("Could not locate symbol [%s]", p);
				free(sd);
				continue;
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

			LOG("Successfully found symbol [%s] in library [0x%lx] @ 0x%lx", p, sd->base_addr, sd->addr);
		}

		sd->whitelist = true;
		strncpy(sd->name, p, sizeof(sd->name));

		vector_push(&function_whitelist, sd);
	}

	if(library_handle != NULL) {
		dlclose(library_handle);
	}

	fclose(fd);

	return OK;
}

uintptr_t get_base_page(uintptr_t addr) {
	uintptr_t page_size = getpagesize();
	return (addr & ~(page_size-1));
}
