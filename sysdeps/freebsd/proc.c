#include "config.h"

#include <sys/param.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <ctype.h>
#include <elf.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <link.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "backend.h"
#include "breakpoint.h"
#include "config.h"
#include "debug.h"
#include "events.h"
#include "library.h"
#include "ltrace-elf.h"
#include "proc.h"

#ifdef	__x86_64__
#define	Elf32_auxv_t	Elf32_Auxinfo
#define	Elf64_auxv_t	Elf64_Auxinfo
#else
#define	Elf32_auxv_t	Elf32_Auxinfo
#define	Elf64_auxv_t	Elf32_Auxinfo
#endif

/*
 * Returns a (malloc'd) file name corresponding to a running pid
 */
char *
pid2name(pid_t pid)
{
	char pathname[PATH_MAX];
	int name[4];
	size_t len;

	name[0] = CTL_KERN;
	name[1] = KERN_PROC;
	name[2] = KERN_PROC_PATHNAME;
	name[3] = pid;

	if (kill(pid, 0) == 0) {
		len = sizeof(pathname);
		if (sysctl(name, 4, pathname, &len, NULL, 0) == 0)
			return strdup(pathname);
	}
	return NULL;
}

static int
fill_kinfo(pid_t pid, struct kinfo_proc *kip)
{
	int name[4];
	size_t len;

	name[0] = CTL_KERN;
	name[1] = KERN_PROC;
	name[2] = KERN_PROC_PID;
	name[3] = pid;

	len = sizeof(*kip);
	if (sysctl(name, 4, kip, &len, NULL, 0) == -1) {
		if (errno != ESRCH)
			perror("sysctl: kern.proc.pid");
		return -1;
	}

	return 0;
}

int
is_vfork(pid_t pid1, pid_t pid2)
{
	struct kinfo_proc ki1;
	struct kinfo_proc ki2;

	if (fill_kinfo(pid1, &ki1) == 0 && fill_kinfo(pid2, &ki2) == 0) {
		if (ki1.ki_vmspace != 0 && ki1.ki_vmspace == ki2.ki_vmspace)
			return 1;
	}

	return 0;
}

pid_t
process_leader(pid_t pid)
{
	return pid;
}

int
process_stopped(pid_t pid)
{
	int is_stopped = -1;
	struct kinfo_proc ki;

	if (fill_kinfo(pid, &ki) == 0) {
		if (ki.ki_stat & SSTOP)
			is_stopped = 1;
		else
			is_stopped = 0;
	}

	return is_stopped;
}

enum process_status
process_status(pid_t pid)
{
	enum process_status ret = PS_INVALID;
	struct kinfo_proc ki;

	if (fill_kinfo(pid, &ki) == 0) {
		switch (ki.ki_stat) {
		case SZOMB:
			ret = PS_ZOMBIE;
			break;
		case SSTOP:
			if (ki.ki_flag & P_TRACED)
				ret = PS_TRACING_STOP;
			else
				ret = PS_STOP;
			break;
		case SSLEEP:
			ret = PS_SLEEPING;
			break;
		}
	} else
		ret = PS_ZOMBIE;

	return ret;
}

int
process_tasks(pid_t pid, pid_t **ret_tasks, size_t *ret_n)
{
	pid_t *tasks = NULL;
	size_t n;

	n = 1;
	tasks = malloc(sizeof(pid_t) * n);
	if (tasks == NULL)
		return -1;
	tasks[0] = pid;
	*ret_tasks = tasks;
	*ret_n = n;
	return 0;
}

/* On native 64-bit system, we need to be careful when handling cross
 * tracing.  This select appropriate pointer depending on host and
 * target architectures.  XXX Really we should abstract this into the
 * ABI object, as theorized about somewhere on pmachata/revamp
 * branch.  */
static void *
select_32_64(struct process *proc, void *p32, void *p64)
{
	if (sizeof(long) == 4 || proc->mask_32bit)
		return p32;
	else
		return p64;
}

static int
fetch_dyn64(struct process *proc, arch_addr_t *addr, Elf64_Dyn *ret)
{
	if (umovebytes(proc, *addr, ret, sizeof(*ret)) != sizeof(*ret))
		return -1;
	*addr += sizeof(*ret);
	return 0;
}

static int
fetch_dyn32(struct process *proc, arch_addr_t *addr, Elf64_Dyn *ret)
{
	Elf32_Dyn dyn;
	if (umovebytes(proc, *addr, &dyn, sizeof(dyn)) != sizeof(dyn))
		return -1;

	*addr += sizeof(dyn);
	ret->d_tag = dyn.d_tag;
	ret->d_un.d_val = dyn.d_un.d_val;

	return 0;
}

static int (*
dyn_fetcher(struct process *proc))(struct process *,
				   arch_addr_t *, Elf64_Dyn *)
{
	return select_32_64(proc, fetch_dyn32, fetch_dyn64);
}

int
proc_find_dynamic_entry_addr(struct process *proc, arch_addr_t src_addr,
			     int d_tag, arch_addr_t *ret)
{
	debug(DEBUG_FUNCTION, "find_dynamic_entry()");

	if (ret == NULL || src_addr == 0 || d_tag < 0)
		return -1;

	int i = 0;
	while (1) {
		Elf64_Dyn entry;
		if (dyn_fetcher(proc)(proc, &src_addr, &entry) < 0
		    || entry.d_tag == DT_NULL
		    || i++ > 100) { /* Arbitrary cut-off so that we
				     * don't loop forever if the
				     * binary is corrupted.  */
			debug(2, "Couldn't find address for dtag!");
			return -1;
		}

		if (entry.d_tag == d_tag) {
			/* XXX The double cast should be removed when
			 * arch_addr_t becomes integral type.  */
			*ret = (arch_addr_t)(uintptr_t)entry.d_un.d_val;
			debug(2, "found address: %p in dtag %d", *ret, d_tag);
			return 0;
		}
	}
}

/* Our own type for representing 32-bit linkmap.  We can't rely on the
 * definition in link.h, because that's only accurate for our host
 * architecture, not for target architecture (where the traced process
 * runs). */
#define LT_LINK_MAP(BITS)			\
	{					\
		Elf##BITS##_Addr l_addr;	\
		Elf##BITS##_Addr l_name;	\
		Elf##BITS##_Addr l_ld;		\
		Elf##BITS##_Addr l_next;	\
		Elf##BITS##_Addr l_prev;	\
	}
struct lt_link_map_32 LT_LINK_MAP(32);
struct lt_link_map_64 LT_LINK_MAP(64);

static int
fetch_lm64(struct process *proc, arch_addr_t addr,
	   struct lt_link_map_64 *ret)
{
	if (umovebytes(proc, addr, ret, sizeof(*ret)) != sizeof(*ret))
		return -1;
	return 0;
}

static int
fetch_lm32(struct process *proc, arch_addr_t addr,
	   struct lt_link_map_64 *ret)
{
	struct lt_link_map_32 lm;
	if (umovebytes(proc, addr, &lm, sizeof(lm)) != sizeof(lm))
		return -1;

	ret->l_addr = lm.l_addr;
	ret->l_name = lm.l_name;
	ret->l_ld = lm.l_ld;
	ret->l_next = lm.l_next;
	ret->l_prev = lm.l_prev;

	return 0;
}

static int (*
lm_fetcher(struct process *proc))(struct process *,
				  arch_addr_t, struct lt_link_map_64 *)
{
	return select_32_64(proc, fetch_lm32, fetch_lm64);
}

/* The same as above holds for struct r_debug.  */
#define LT_R_DEBUG(BITS)			\
	{					\
		int r_version;			\
		Elf##BITS##_Addr r_map;		\
		Elf##BITS##_Addr r_brk;		\
		int r_state;			\
		Elf##BITS##_Addr r_ldbase;	\
	}

struct lt_r_debug_32 LT_R_DEBUG(32);
struct lt_r_debug_64 LT_R_DEBUG(64);

static int
fetch_rd64(struct process *proc, arch_addr_t addr,
	   struct lt_r_debug_64 *ret)
{
	if (umovebytes(proc, addr, ret, sizeof(*ret)) != sizeof(*ret))
		return -1;
	return 0;
}

static int
fetch_rd32(struct process *proc, arch_addr_t addr,
	   struct lt_r_debug_64 *ret)
{
	struct lt_r_debug_32 rd;
	if (umovebytes(proc, addr, &rd, sizeof(rd)) != sizeof(rd))
		return -1;

	ret->r_version = rd.r_version;
	ret->r_map = rd.r_map;
	ret->r_brk = rd.r_brk;
	ret->r_state = rd.r_state;
	ret->r_ldbase = rd.r_ldbase;

	return 0;
}

static int (*
rdebug_fetcher(struct process *proc))(struct process *,
				      arch_addr_t, struct lt_r_debug_64 *)
{
	return select_32_64(proc, fetch_rd32, fetch_rd64);
}

static int
fetch_auxv64_entry(int fd, Elf64_auxv_t *ret)
{
	/* Reaching EOF is as much problem as not reading whole
	 * entry.  */
	return read(fd, ret, sizeof(*ret)) == sizeof(*ret) ? 0 : -1;
}

static int
fetch_auxv32_entry(int fd, Elf64_auxv_t *ret)
{
	Elf32_auxv_t auxv;
	if (read(fd, &auxv, sizeof(auxv)) != sizeof(auxv))
		return -1;

	ret->a_type = auxv.a_type;
	ret->a_un.a_val = auxv.a_un.a_val;
	return 0;
}

static int (*
auxv_fetcher(struct process *proc))(int, Elf64_auxv_t *)
{
	return select_32_64(proc, fetch_auxv32_entry, fetch_auxv64_entry);
}

static void
crawl_linkmap(struct process *proc, struct lt_r_debug_64 *dbg)
{
	debug (DEBUG_FUNCTION, "crawl_linkmap()");

	if (!dbg || !dbg->r_map) {
		debug(2, "Debug structure or it's linkmap are NULL!");
		return;
	}

	/* XXX The double cast should be removed when
	 * arch_addr_t becomes integral type.  */
	arch_addr_t addr = (arch_addr_t)(uintptr_t)dbg->r_map;

	while (addr != 0) {
		struct lt_link_map_64 rlm = {};
		if (lm_fetcher(proc)(proc, addr, &rlm) < 0) {
			debug(2, "Unable to read link map");
			return;
		}

		arch_addr_t key = addr;
		/* XXX The double cast should be removed when
		 * arch_addr_t becomes integral type.  */
		addr = (arch_addr_t)(uintptr_t)rlm.l_next;
		if (rlm.l_name == 0) {
			debug(2, "Name of mapped library is NULL");
			return;
		}

		char lib_name[BUFSIZ];
		/* XXX The double cast should be removed when
		 * arch_addr_t becomes integral type.  */
		umovebytes(proc, (arch_addr_t)(uintptr_t)rlm.l_name,
			   lib_name, sizeof(lib_name));

		/* Skip empty library names. Also skip run-time link-editor,
		 * because its name hardcoded that causes impossibility
		 * of tracing 32-bit binaries on 64-bit machine. */
		if (*lib_name == 0 ||
		    strcmp(lib_name, proc->filename) == 0 ||
		    strcmp(lib_name, "/libexec/ld-elf.so.1") == 0)
			continue;

		/* Do we have that library already?  */
		if (proc_each_library(proc, NULL, library_with_key_cb, &key))
			continue;

		struct library *lib = malloc(sizeof(*lib));
		if (lib == NULL) {
		fail:
			if (lib != NULL)
				library_destroy(lib);
			fprintf(stderr, "Couldn't load ELF object %s: %s\n",
				lib_name, strerror(errno));
			continue;
		}
		library_init(lib, LT_LIBTYPE_DSO);

		if (ltelf_read_library(lib, proc, lib_name, rlm.l_addr) < 0)
			goto fail;

		lib->key = key;
		proc_add_library(proc, lib);
	}
	return;
}

static int
load_debug_struct(struct process *proc, struct lt_r_debug_64 *ret)
{
	debug(DEBUG_FUNCTION, "load_debug_struct");

	if (rdebug_fetcher(proc)(proc, proc->os.debug_addr, ret) < 0) {
		debug(2, "This process does not have a debug structure!");
		return -1;
	}

	return 0;
}

static void
rdebug_bp_on_hit(struct breakpoint *bp, struct process *proc)
{
	debug(DEBUG_FUNCTION, "arch_check_dbg");

	struct lt_r_debug_64 rdbg;
	if (load_debug_struct(proc, &rdbg) < 0) {
		debug(2, "Unable to load debug structure!");
		return;
	}

	if (rdbg.r_state == RT_CONSISTENT) {
		debug(2, "Linkmap is now consistent");
		switch (proc->os.debug_state) {
		case RT_ADD:
			debug(2, "Adding DSO to linkmap");
			crawl_linkmap(proc, &rdbg);
			break;
		case RT_DELETE:
			debug(2, "Removing DSO from linkmap");
			// XXX unload that library
			break;
		default:
			debug(2, "Unexpected debug state!");
		}
	}

	proc->os.debug_state = rdbg.r_state;
}

#ifndef ARCH_HAVE_FIND_DL_DEBUG
int
arch_find_dl_debug(struct process *proc, arch_addr_t dyn_addr,
		   arch_addr_t *ret)
{
	return proc_find_dynamic_entry_addr(proc, dyn_addr, DT_DEBUG, ret);
}
#endif

int
linkmap_init(struct process *proc, arch_addr_t dyn_addr)
{
	debug(DEBUG_FUNCTION, "linkmap_init(%d, dyn_addr=%p)", proc->pid, dyn_addr);

	if (arch_find_dl_debug(proc, dyn_addr, &proc->os.debug_addr) == -1) {
		debug(2, "Couldn't find debug structure!");
		return -1;
	}

	int status;
	struct lt_r_debug_64 rdbg;
	if ((status = load_debug_struct(proc, &rdbg)) < 0) {
		debug(2, "No debug structure or no memory to allocate one!");
		return status;
	}

	/* XXX The double cast should be removed when
	 * arch_addr_t becomes integral type.  */
	arch_addr_t addr = (arch_addr_t)(uintptr_t)rdbg.r_brk;
	if (arch_translate_address_dyn(proc, addr, &addr) < 0)
		return -1;

	struct breakpoint *rdebug_bp = insert_breakpoint(proc, addr, NULL);
	static struct bp_callbacks rdebug_callbacks = {
		.on_hit = rdebug_bp_on_hit,
	};
	rdebug_bp->cbs = &rdebug_callbacks;

	crawl_linkmap(proc, &rdbg);

	return 0;
}

int
task_kill(pid_t pid, int sig)
{
	return kill(pid, sig);
}

void
process_removed(struct process *proc)
{
	delete_events_for(proc);
}

int
process_get_entry(struct process *proc,
		  arch_addr_t *entryp,
		  arch_addr_t *interp_biasp)
{
	fprintf(stderr, "%s not implemented", __func__);
	exit(1);
#if notyet
	PROC_PID_FILE(fn, "/proc/%d/auxv", proc->pid);
	int fd = open(fn, O_RDONLY);
#else
	char *fn = "";
	int fd = 0;
#endif
	int ret = 0;
	if (fd == -1) {
	fail:
		fprintf(stderr, "couldn't read %s: %s", fn, strerror(errno));
		ret = -1;
	done:
		if (fd != -1)
			close(fd);
		return ret;
	}

	arch_addr_t at_entry = 0;
	arch_addr_t at_bias = 0;
	while (1) {
		Elf64_auxv_t entry = {};
		if (auxv_fetcher(proc)(fd, &entry) < 0)
			goto fail;

		switch (entry.a_type) {
		case AT_BASE:
			/* XXX The double cast should be removed when
			 * arch_addr_t becomes integral type.  */
			at_bias = (arch_addr_t)(uintptr_t)entry.a_un.a_val;
			continue;

		case AT_ENTRY:
			/* XXX The double cast should be removed when
			 * arch_addr_t becomes integral type.  */
			at_entry = (arch_addr_t)(uintptr_t)entry.a_un.a_val;
		default:
			continue;

		case AT_NULL:
			break;
		}
		break;
	}

	if (entryp != NULL)
		*entryp = at_entry;
	if (interp_biasp != NULL)
		*interp_biasp = at_bias;
	goto done;
}

int
os_process_init(struct process *proc)
{
	bzero(&proc->os, sizeof(proc->os));
	return 0;
}

void
os_process_destroy(struct process *proc)
{
}

int
os_process_clone(struct process *retp, struct process *proc)
{
	retp->os = proc->os;
	return 0;
}

int
os_process_exec(struct process *proc)
{
	return 0;
}
