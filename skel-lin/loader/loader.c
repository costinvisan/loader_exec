/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "exec_parser.h"
#include "utils.h"

#define FULL_PERMISSIONS PROT_READ | PROT_EXEC | PROT_WRITE

static so_exec_t *exec;
static struct sigaction old_act;
int fd;

static void handler(int signum, siginfo_t *info, void *context)
{
	int i;
	int segment = 0;
	int size_page = getpagesize();
	char *addr_fault = (char *)info->si_addr;
	for (i = 0; i < exec->segments_no; ++i)
	{
		unsigned int perms = exec->segments[i].perm;
		int idx_page = (addr_fault - (char *)exec->segments[i].vaddr) / size_page;
		char *addr_mem = (char *)exec->segments[i].vaddr + exec->segments[i].mem_size;
		char *addr_file = (char *)exec->segments[i].vaddr + exec->segments[i].file_size;

		if (addr_fault <= addr_mem)
		{
			if (info->si_code == SEGV_MAPPER)
			{
				int flags;
				char *addr_mapped;
				char *addr_aligned = (char *)ALIGN_DOWN((uintptr_t)addr_fault, size_page);
				off_t offset = size_page * idx_page + exec->segments[i].offset;
				
				if (file_address >= faultAddress && mem_address <= faultAddress)
				{
					flags = MAP_FIXED | MAP_PRIVATE;
				}
				else
				{
					flags = MAP_ANONYMOUS | MAP_PRIVATE;
				}

				addr_mapped = mmap(addr_aligned, size_page, FULL_PERMISSIONS, flags, fd, offset);
				DIE(addr_mapped == MAP_FAILED, "mmap error");

				memset(addr_mapped, 0, size_page);
				
				int size;
				int flag_read = 0;

				if (addr_aligned + size_page > addr_file &&
					exec->segments[i].mem_size > exec->segments[i].file_size)
				{
					if (addr_aligned < file_address)
					{
						size = addr_file - addr_aligned;
						flag_read = 1;
					}
				}
				else
				{
					size = size_page;
					flag_read = 1;
				}

				if (flag_read)
				{
					char *content = calloc(size, sizeof(char));
					lseek(fd, 0, SEEK_SET);
					lseek(fd, offset, SEEK_SET);
					read(fd, content, size);
					memcpy(addr_mapped, content, size);
					free(content)
				}
				
			}
		}
		else
		{
			segment++;
		}

	}
}

int so_init_loader(void)
{
	int check_err;
	struct sigaction act;

	act.sa_sigaction = handler;
	action.sa_flags = SA_SIGINFO;

	check_err = sigemptyset(&act.sa_mask);
	DIE(check_err == -1, "sigemptyset error");

	check_err = sigaddset(&act.sa_mask, SIGSEGV);
	DIE(check_err == -1, "sigaddset error");

	check_err = sigaction(SIGSEGV, &act, &old_act);
	DIE(check_err == -1, "sigaction error");

	return -1;
}

int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	return -1;
}
