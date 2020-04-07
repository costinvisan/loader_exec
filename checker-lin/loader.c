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
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

#include "exec_parser.h"
#include "utils.h"

#define FLAGS_MAP MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS

static so_exec_t *exec;
static struct sigaction old_act;
int fd;
int size_page;

static void handler(int signum, siginfo_t *info, void *context)
{
	/* call default handler */
	if (signum != SIGSEGV) {
		old_act.sa_sigaction(signum, info, context);
		return;
	}

	int i;
	int segment = -1;
	char *addr_fault = (char *)info->si_addr;

	/* Find the segment for which SIGSEV occured */
	for (i = 0; i < exec->segments_no; ++i) {
		char *addr_mem =
			(char *)exec->segments[i].vaddr +
			exec->segments[i].mem_size;

		if (addr_fault <= addr_mem) {
			segment = i;
			break;
		}
	}

	if (segment != -1) {
		/* Check if address was mapped */
		if (info->si_code == SEGV_MAPERR) {
			int check_err, idx_page, size = 0;
			char *addr_mapped, *addr_file, *addr_align, *vaddr;

			/* Align down the address */
			addr_align =
				(char *)((uintptr_t)addr_fault &
				(~(size_page - 1)));
			vaddr = (char *)exec->segments[segment].vaddr;
			addr_file = vaddr + exec->segments[segment].file_size;
			idx_page = (addr_fault - vaddr) / size_page;

			/* Map the aligned addres with map fixed
			 * and change permissions so we can copy the data
			 */
			addr_mapped = mmap(addr_align,
				size_page,
				PROT_WRITE,
				FLAGS_MAP,
				-1, 0);
			DIE(addr_mapped == MAP_FAILED, "mmap error");
			memset(addr_mapped, 0, size_page);
			/* Decide the size we need to read from file in
			 * the address just maped
			 */
			if (exec->segments[segment].mem_size >
				exec->segments[segment].file_size &&
				addr_align + size_page > addr_file) {
				if (addr_align < addr_file)
					size = addr_file - addr_align;
			} else {
				size = size_page;
			}

			lseek(fd,
				exec->segments[segment].offset +
				idx_page * size_page,
				SEEK_SET);
			read(fd, addr_mapped, size);

			/* Restore permissions */
			check_err = mprotect(addr_mapped,
				size_page,
				exec->segments[segment].perm);
			DIE(check_err == -1, "mprotect error");
		} else {
			/* Already in a maped page
			 * so we call the default handler
			 */
			old_act.sa_sigaction(signum, info, context);
		}
	} else {
		/* Not in a known segment
		 * so we call the default handler
		 */
		old_act.sa_sigaction(signum, info, context);
	}
}

int so_init_loader(void)
{
	struct sigaction action;
	int check_err;

	action.sa_sigaction = handler;
	action.sa_flags = SA_SIGINFO;

	size_page = getpagesize();

	check_err = sigemptyset(&action.sa_mask);
	DIE(check_err == -1, "sigemptyset error");

	check_err = sigaddset(&action.sa_mask, SIGSEGV);
	DIE(check_err == -1, "sigaddset error");

	check_err = sigaction(SIGSEGV, &action, &old_act);
	DIE(check_err == -1, "sigaction");

	return -1;
}

int so_execute(char *path, char *argv[])
{
	fd = open(path, O_RDWR);

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	return -1;
}
