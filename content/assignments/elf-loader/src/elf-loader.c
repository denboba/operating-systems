// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);
	Elf64_Ehdr *ehdr_temp = (Elf64_Ehdr *)elf_contents;

	// Make a copy of the ELF header since we might overwrite the file mapping
	Elf64_Ehdr ehdr_copy;
	memcpy(&ehdr_copy, ehdr_temp, sizeof(Elf64_Ehdr));
	Elf64_Ehdr *ehdr = &ehdr_copy;

	// Part 1: ELF Header Validation
	// Validate ELF magic bytes
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stderr, "Not a valid ELF file\n");
		exit(3);
	}

	// Validate ELF class is 64-bit
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}

	// Get program headers and make a copy
	Elf64_Phdr *phdr_temp = (Elf64_Phdr *)((char *)elf_contents + ehdr->e_phoff);
	size_t phdr_size = ehdr->e_phnum * sizeof(Elf64_Phdr);
	Elf64_Phdr *phdr = malloc(phdr_size);
	if (!phdr) {
		perror("malloc");
		exit(1);
	}
	memcpy(phdr, phdr_temp, phdr_size);

	// Determine if this is a PIE executable
	int is_pie = (ehdr->e_type == ET_DYN);
	void *load_base = NULL;

	// For PIE, extract relocation information from DYNAMIC segment before mapping
	Elf64_Addr pie_rela_addr = 0;
	size_t pie_rela_size = 0;
	size_t pie_rela_ent = sizeof(Elf64_Rela);
	
	if (is_pie) {
		// Find and parse the DYNAMIC segment
		for (int i = 0; i < ehdr->e_phnum; i++) {
			Elf64_Phdr *p = &phdr[i];
			if (p->p_type == PT_DYNAMIC) {
				Elf64_Dyn *dyn = (Elf64_Dyn *)((char *)elf_contents + p->p_offset);
				for (; dyn->d_tag != DT_NULL; dyn++) {
					if (dyn->d_tag == DT_RELA) {
						pie_rela_addr = dyn->d_un.d_ptr;
					} else if (dyn->d_tag == DT_RELASZ) {
						pie_rela_size = dyn->d_un.d_val;
					} else if (dyn->d_tag == DT_RELAENT) {
						pie_rela_ent = dyn->d_un.d_val;
					}
				}
				break;
			}
		}
	}

	// Part 5: For PIE executables, choose a random load base
	if (is_pie) {
		// Use a random base address for PIE
		// We'll let mmap choose the address for the first segment
		load_base = NULL; // Will be set when we map the first segment
	}

	// Part 2 & 3: Load PT_LOAD segments
	void *first_load_addr = NULL;
	Elf64_Addr min_vaddr = (Elf64_Addr)-1;
	
	// First pass: find minimum virtual address for PIE
	if (is_pie) {
		for (int i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type == PT_LOAD) {
				if (phdr[i].p_vaddr < min_vaddr) {
					min_vaddr = phdr[i].p_vaddr;
				}
			}
		}
	}

	// Load all PT_LOAD segments
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			// Convert program header flags to mmap protection flags
			int prot = 0;
			if (phdr[i].p_flags & PF_R) prot |= PROT_READ;
			if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE;
			if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC;

			// Calculate addresses
			Elf64_Addr vaddr = phdr[i].p_vaddr;
			size_t offset = phdr[i].p_offset;
			size_t filesz = phdr[i].p_filesz;
			size_t memsz = phdr[i].p_memsz;

			// Align to page boundary
			Elf64_Addr page_aligned_vaddr = vaddr & ~(0x1000 - 1);
			size_t page_offset = vaddr - page_aligned_vaddr;
			size_t total_size = page_offset + memsz;

			void *target_addr;
			if (is_pie) {
				if (load_base == NULL) {
					// First segment - let mmap choose address
					target_addr = NULL;
				} else {
					// Subsequent segments - use offset from load_base
					target_addr = (char *)load_base + (page_aligned_vaddr - min_vaddr);
				}
			} else {
				// Non-PIE: use absolute address
				target_addr = (void *)page_aligned_vaddr;
			}

			// Map the segment
			void *mapped = mmap(target_addr, total_size,
					    PROT_READ | PROT_WRITE | PROT_EXEC,
					    MAP_PRIVATE | MAP_ANONYMOUS |
					    (is_pie && load_base == NULL ? 0 : MAP_FIXED),
					    -1, 0);

			if (mapped == MAP_FAILED) {
				perror("mmap segment");
				exit(1);
			}

			// Set load_base from first mapped segment for PIE
			if (is_pie && load_base == NULL) {
				load_base = (char *)mapped - (page_aligned_vaddr - min_vaddr);
				first_load_addr = mapped;
			}

			// Copy data from file
			if (filesz > 0) {
				memcpy((char *)mapped + page_offset,
				       (char *)elf_contents + offset, filesz);
			}

			// Zero out the rest (BSS section)
			if (memsz > filesz) {
				memset((char *)mapped + page_offset + filesz, 0,
				       memsz - filesz);
			}

			// Don't set final permissions yet if PIE (need to do relocations first)
			// For non-PIE, set permissions now
			if (!is_pie) {
				if (mprotect(mapped, total_size, prot) < 0) {
					perror("mprotect");
					exit(1);
				}
			}
		}
	}

	// Part 5: Process relocations for PIE
	if (is_pie && pie_rela_addr && pie_rela_size > 0) {
		// pie_rela_addr is a virtual address, find it in the file
		Elf64_Rela *rela = NULL;
		for (int j = 0; j < ehdr->e_phnum; j++) {
			if (phdr[j].p_type == PT_LOAD &&
			    pie_rela_addr >= phdr[j].p_vaddr &&
			    pie_rela_addr < phdr[j].p_vaddr + phdr[j].p_filesz) {
				size_t offset_in_segment = pie_rela_addr - phdr[j].p_vaddr;
				rela = (Elf64_Rela *)((char *)load_base + pie_rela_addr);
				break;
			}
		}

		if (rela) {
			size_t rela_count = pie_rela_size / pie_rela_ent;
			for (size_t j = 0; j < rela_count; j++) {
				if (ELF64_R_TYPE(rela[j].r_info) == R_X86_64_RELATIVE) {
					uint64_t *reloc_addr = (uint64_t *)((char *)load_base + rela[j].r_offset);
					*reloc_addr = (uint64_t)load_base + rela[j].r_addend;
				}
			}
		}

		// Now set correct permissions for all segments
		for (int i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type == PT_LOAD) {
				int prot = 0;
				if (phdr[i].p_flags & PF_R) prot |= PROT_READ;
				if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE;
				if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC;

				Elf64_Addr vaddr = phdr[i].p_vaddr;
				size_t memsz = phdr[i].p_memsz;
				Elf64_Addr page_aligned_vaddr = vaddr & ~(0x1000 - 1);
				size_t page_offset = vaddr - page_aligned_vaddr;
				size_t total_size = page_offset + memsz;
				
				void *mapped = (char *)load_base + page_aligned_vaddr;
				if (mprotect(mapped, total_size, prot) < 0) {
					perror("mprotect after relocation");
					exit(1);
				}
			}
		}
	}

	// Part 4: Set up stack for libc binaries
	// Get stack size limit
	struct rlimit lim;
	getrlimit(RLIMIT_STACK, &lim);
	size_t stack_size = (lim.rlim_cur != RLIM_INFINITY) ? lim.rlim_cur : 8 * 1024 * 1024;

	// Allocate stack
	void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
	if (stack == MAP_FAILED) {
		perror("mmap stack");
		exit(1);
	}

	// Stack grows downward, so start from the top
	void *sp = (char *)stack + stack_size;

	// Align stack to 16 bytes
	sp = (void *)((uintptr_t)sp & ~0xF);

	// Count environment variables
	int envc = 0;
	while (envp[envc] != NULL) envc++;

	// Generate 16 random bytes for AT_RANDOM
	char random_bytes[16];
	int urandom = open("/dev/urandom", O_RDONLY);
	if (urandom >= 0) {
		read(urandom, random_bytes, 16);
		close(urandom);
	} else {
		// Fallback to time-based random
		srand(time(NULL));
		for (int i = 0; i < 16; i++) {
			random_bytes[i] = rand() & 0xFF;
		}
	}

	// Calculate total space needed
	// We need to place strings at the top, then pointers, then argc
	// Layout (from high to low address):
	// - argv strings
	// - envp strings
	// - random bytes
	// - NULL
	// - auxv entries (key-value pairs)
	// - NULL
	// - envp pointers
	// - NULL
	// - argv pointers
	// - argc

	// First, calculate sizes and place strings
	char *string_ptr = (char *)sp;
	
	// Reserve space for strings first (going downward)
	for (int i = 0; i < argc; i++) {
		string_ptr -= strlen(argv[i]) + 1;
	}
	for (int i = 0; i < envc; i++) {
		string_ptr -= strlen(envp[i]) + 1;
	}
	string_ptr -= 16; // for AT_RANDOM bytes
	
	// Align string pointer
	string_ptr = (char *)((uintptr_t)string_ptr & ~0xF);
	
	// Now copy strings and record their addresses
	char **argv_strs = malloc(argc * sizeof(char *));
	char **envp_strs = malloc(envc * sizeof(char *));
	char *current_str = string_ptr;
	
	for (int i = 0; i < argc; i++) {
		argv_strs[i] = current_str;
		strcpy(current_str, argv[i]);
		current_str += strlen(argv[i]) + 1;
	}
	
	for (int i = 0; i < envc; i++) {
		envp_strs[i] = current_str;
		strcpy(current_str, envp[i]);
		current_str += strlen(envp[i]) + 1;
	}
	
	char *random_ptr = current_str;
	memcpy(random_ptr, random_bytes, 16);

	// Now build the stack structure
	uint64_t *stack_ptr = (uint64_t *)string_ptr;

	// Auxiliary vector
	#define PUSH_AUXV(key, val) do { \
		stack_ptr -= 2; \
		stack_ptr[0] = (key); \
		stack_ptr[1] = (uint64_t)(val); \
	} while(0)

	// AT_NULL terminates the auxiliary vector
	PUSH_AUXV(AT_NULL, 0);

	// Required auxiliary vector entries
	PUSH_AUXV(AT_RANDOM, random_ptr);
	PUSH_AUXV(AT_PAGESZ, getpagesize());
	PUSH_AUXV(AT_UID, getuid());
	PUSH_AUXV(AT_EUID, geteuid());
	PUSH_AUXV(AT_GID, getgid());
	PUSH_AUXV(AT_EGID, getegid());

	// Program header information
	void *phdr_addr;
	if (is_pie) {
		phdr_addr = (char *)load_base + ehdr->e_phoff;
	} else {
		// For non-PIE, find the PT_PHDR segment or use ehdr location
		Elf64_Addr phdr_vaddr = 0;
		for (int i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type == PT_PHDR) {
				phdr_vaddr = phdr[i].p_vaddr;
				break;
			}
		}
		if (phdr_vaddr == 0) {
			// If no PT_PHDR, calculate from first LOAD segment
			for (int i = 0; i < ehdr->e_phnum; i++) {
				if (phdr[i].p_type == PT_LOAD) {
					phdr_vaddr = phdr[i].p_vaddr + ehdr->e_phoff - phdr[i].p_offset;
					break;
				}
			}
		}
		phdr_addr = (void *)phdr_vaddr;
	}

	PUSH_AUXV(AT_PHDR, phdr_addr);
	PUSH_AUXV(AT_PHENT, ehdr->e_phentsize);
	PUSH_AUXV(AT_PHNUM, ehdr->e_phnum);
	PUSH_AUXV(AT_ENTRY, is_pie ? (uint64_t)((char *)load_base + ehdr->e_entry) : (uint64_t)ehdr->e_entry);

	// envp pointers (NULL terminated)
	stack_ptr--;
	*stack_ptr = 0;
	for (int i = envc - 1; i >= 0; i--) {
		stack_ptr--;
		*stack_ptr = (uint64_t)envp_strs[i];
	}

	// argv pointers (NULL terminated)
	stack_ptr--;
	*stack_ptr = 0;
	for (int i = argc - 1; i >= 0; i--) {
		stack_ptr--;
		*stack_ptr = (uint64_t)argv_strs[i];
	}

	// argc
	stack_ptr--;
	*stack_ptr = argc;

	// Ensure stack is 16-byte aligned
	sp = stack_ptr;
	if ((uintptr_t)sp & 0xF) {
		sp = (void *)((uintptr_t)sp & ~0xFUL);
	}

	// Calculate entry point
	void (*entry)();
	if (is_pie) {
		entry = (void (*)())((char *)load_base + ehdr->e_entry);
	} else {
		entry = (void (*)())ehdr->e_entry;
	}

	// Clean up
	free(argv_strs);
	free(envp_strs);
	free(phdr);

	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
