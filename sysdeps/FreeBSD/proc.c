#define _GNU_SOURCE /* For getline.  */
#include "config.h"

#include <sys/param.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <ctype.h>
#include <err.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <link.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "breakpoint.h"
#include "proc.h"
#include "library.h"

#ifndef	__NR_tkill
#define	__NR_tkill	SYS_thr_kill
#endif

#ifndef	DT_NUM
#define	DT_NUM	DT_MAXPOSTAGS
#endif

/*
 * Returns a (malloc'd) file name corresponding to a running pid
 */
char *
pid2name(pid_t pid) {
	char pathname[PATH_MAX];
	int name[4];
	size_t len;

	name[0] = CTL_KERN;
	name[1] = KERN_PROC;
	name[2] = KERN_PROC_PATHNAME;
	name[3] = pid;

	if (!kill(pid, 0)) {
		len = sizeof(pathname);
		if (sysctl(name, 4, pathname, &len, NULL, 0) == 0)
			return strdup(pathname);
	}
	return (NULL);
}

static struct kinfo_proc *
fill_kinfo(pid_t pid)
{
	struct kinfo_proc *kip;
	int name[4];
	size_t len;

	name[0] = CTL_KERN;
	name[1] = KERN_PROC;
	name[2] = KERN_PROC_PID | KERN_PROC_INC_THREAD;
	name[3] = pid;

	len = 0;
	if (sysctl(name, 4, NULL, &len, NULL, 0) == -1) {
		warn("sysctl: kern.proc.pid: %d", pid);
		return (NULL);
	}

	kip = malloc(len);
	if (kip == NULL)
		err(1, "malloc");

	if (sysctl(name, 4, kip, &len, NULL, 0) == -1) {
		warn("sysctl: kern.proc.pid: %d", pid);
		free(kip);
		return (NULL);
	}

	return (kip);
}

pid_t
process_leader(pid_t pid)
{
#ifdef notyet
	pid_t tgid = 0;
	struct kinfo_proc *kip = fill_kinfo(pid);

	if (kip != NULL) {
		tgid = kip->ki_tid;
		free(kip);
	}

	return (tgid);
#endif
	return (pid);
}

int
process_stopped(pid_t pid)
{
	int is_stopped = -1;
	struct kinfo_proc *kip = fill_kinfo(pid);

	if (kip != NULL) {
		if (kip->ki_stat & SSTOP)
			is_stopped = 0;
		free(kip);
	}

	return (is_stopped);
}

enum process_status
process_status(pid_t pid)
{
	enum process_status ret = ps_invalid;
	struct kinfo_proc *kip = fill_kinfo(pid);

	if (kip != NULL) {
		switch (kip->ki_stat) {
		case SZOMB:
			ret = ps_zombie;
			break;
		case SSTOP:
			if (kip->ki_flag & P_TRACED)
				ret = ps_tracing_stop;
			else
				ret = ps_stop;
			break;
		case SSLEEP:
			ret = ps_sleeping;
			break;
		}
		free(kip);
		if (ret == ps_invalid)
			fprintf(stderr, "process_status %d: %s", pid,
				strerror(errno));
	} else
		/* If the file is not present, the process presumably
		 * exited already.  */
		ret = ps_zombie;

	return (ret);
}

int
process_tasks(pid_t pid, pid_t **ret_tasks, size_t *ret_n)
{
	pid_t *tasks = NULL;
	size_t i, n;
	struct kinfo_proc *kip = fill_kinfo(pid);

	if (kip == NULL)
		return (-1);

	n = kip->ki_numthreads;
	tasks = malloc(sizeof(pid_t) * n);
	if (tasks == NULL) {
		free(kip);
		return (-1);
	}

	tasks[0] = kip[n - 1].ki_pid;
	for (i = 1; i < n; i++)
		tasks[i] = kip[n - i - 1].ki_tid;

	free(kip);
	*ret_tasks = tasks;
	*ret_n = n;
	return (0);
}

/* On native 64-bit system, we need to be careful when handling cross
 * tracing.  This select appropriate pointer depending on host and
 * target architectures.  XXX Really we should abstract this into the
 * ABI object, as theorized about somewhere on pmachata/revamp
 * branch.  */
static void *
select_32_64(struct Process *proc, void *p32, void *p64)
{
	if (sizeof(long) == 4 || proc->mask_32bit)
		return p32;
	else
		return p64;
}

static int
fetch_dyn64(struct Process *proc, target_address_t *addr, Elf64_Dyn *ret)
{
	if (umovebytes(proc, *addr, ret, sizeof(*ret)) != sizeof(*ret))
		return -1;
	*addr += sizeof(*ret);
	return 0;
}

static int
fetch_dyn32(struct Process *proc, target_address_t *addr, Elf64_Dyn *ret)
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
dyn_fetcher(struct Process *proc))(struct Process *,
				   target_address_t *, Elf64_Dyn *)
{
	return select_32_64(proc, fetch_dyn32, fetch_dyn64);
}

static int
find_dynamic_entry_addr(struct Process *proc, target_address_t src_addr,
			int d_tag, target_address_t *ret)
{
	debug(DEBUG_FUNCTION, "find_dynamic_entry()");

	if (ret == NULL || src_addr == 0 || d_tag < 0 || d_tag > DT_NUM)
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
			 * target_address_t becomes integral type.  */
			*ret = (target_address_t)(uintptr_t)entry.d_un.d_val;
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
fetch_lm64(struct Process *proc, target_address_t addr,
	   struct lt_link_map_64 *ret)
{
	if (umovebytes(proc, addr, ret, sizeof(*ret)) != sizeof(*ret))
		return -1;
	return 0;
}

static int
fetch_lm32(struct Process *proc, target_address_t addr,
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
lm_fetcher(struct Process *proc))(struct Process *,
				  target_address_t, struct lt_link_map_64 *)
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
fetch_rd64(struct Process *proc, target_address_t addr,
	   struct lt_r_debug_64 *ret)
{
	if (umovebytes(proc, addr, ret, sizeof(*ret)) != sizeof(*ret))
		return -1;
	return 0;
}

static int
fetch_rd32(struct Process *proc, target_address_t addr,
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
rdebug_fetcher(struct Process *proc))(struct Process *,
				      target_address_t, struct lt_r_debug_64 *)
{
	return select_32_64(proc, fetch_rd32, fetch_rd64);
}

static void
crawl_linkmap(struct Process *proc, struct lt_r_debug_64 *dbg)
{
	debug (DEBUG_FUNCTION, "crawl_linkmap()");

	if (!dbg || !dbg->r_map) {
		debug(2, "Debug structure or it's linkmap are NULL!");
		return;
	}

	/* FIXME: zont */
	return;

	/* XXX The double cast should be removed when
	 * target_address_t becomes integral type.  */
	target_address_t addr = (target_address_t)(uintptr_t)dbg->r_map;

	while (addr != 0) {
		struct lt_link_map_64 rlm;
		if (lm_fetcher(proc)(proc, addr, &rlm) < 0) {
			debug(2, "Unable to read link map");
			return;
		}

		target_address_t key = addr;
		/* XXX The double cast should be removed when
		 * target_address_t becomes integral type.  */
		addr = (target_address_t)(uintptr_t)rlm.l_next;
		if (rlm.l_name == 0) {
			debug(2, "Name of mapped library is NULL");
			return;
		}

		char lib_name[BUFSIZ];
		/* XXX The double cast should be removed when
		 * target_address_t becomes integral type.  */
		umovebytes(proc, (target_address_t)(uintptr_t)rlm.l_name,
			   lib_name, sizeof(lib_name));

		if (*lib_name == '\0') {
			/* VDSO.  No associated file, XXX but we might
			 * load it from the address space of the
			 * process.  */
			continue;
		}

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

/* A struct stored at proc->debug.  */
struct debug_struct
{
	target_address_t debug_addr;
	int state;
};

static int
load_debug_struct(struct Process *proc, struct lt_r_debug_64 *ret)
{
	debug(DEBUG_FUNCTION, "load_debug_struct");

	struct debug_struct *debug = proc->debug;

	if (rdebug_fetcher(proc)(proc, debug->debug_addr, ret) < 0) {
		debug(2, "This process does not have a debug structure!\n");
		return -1;
	}

	return 0;
}

static void
rdebug_bp_on_hit(struct breakpoint *bp, struct Process *proc)
{
	debug(DEBUG_FUNCTION, "arch_check_dbg");

	struct lt_r_debug_64 rdbg;
	if (load_debug_struct(proc, &rdbg) < 0) {
		debug(2, "Unable to load debug structure!");
		return;
	}

	struct debug_struct *debug = proc->debug;
	if (rdbg.r_state == RT_CONSISTENT) {
		debug(2, "Linkmap is now consistent");
		if (debug->state == RT_ADD) {
			debug(2, "Adding DSO to linkmap");
			//data.proc = proc;
			crawl_linkmap(proc, &rdbg);
			//&data);
		} else if (debug->state == RT_DELETE) {
			debug(2, "Removing DSO from linkmap");
		} else {
			debug(2, "Unexpected debug state!");
		}
	}

	debug->state = rdbg.r_state;
}

int
linkmap_init(struct Process *proc, target_address_t dyn_addr)
{
	debug(DEBUG_FUNCTION, "linkmap_init()");

	struct debug_struct *debug = malloc(sizeof(*debug));
	if (debug == NULL) {
		fprintf(stderr, "couldn't allocate debug struct: %s\n",
			strerror(errno));
	fail:
		proc->debug = NULL;
		free(debug);
		return -1;
	}
	proc->debug = debug;

	if (find_dynamic_entry_addr(proc, dyn_addr, DT_DEBUG,
				    &debug->debug_addr) == -1) {
		debug(2, "Couldn't find debug structure!");
		goto fail;
	}

	int status;
	struct lt_r_debug_64 rdbg;
	if ((status = load_debug_struct(proc, &rdbg)) < 0) {
		debug(2, "No debug structure or no memory to allocate one!");
		return status;
	}

	/* XXX The double cast should be removed when
	 * target_address_t becomes integral type.  */
	target_address_t addr = (target_address_t)(uintptr_t)rdbg.r_brk;
	if (arch_translate_address_dyn(proc, addr, &addr) < 0)
		goto fail;

	struct breakpoint *rdebug_bp = insert_breakpoint(proc, addr, NULL);
	static struct bp_callbacks rdebug_callbacks = {
		.on_hit = rdebug_bp_on_hit,
	};
	rdebug_bp->cbs = &rdebug_callbacks;

	crawl_linkmap(proc, &rdbg);

	return 0;
}

int
task_kill (pid_t pid, int sig)
{
#ifdef	notyet
	// Taken from GDB
        int ret;

        errno = 0;
        ret = syscall (__NR_tkill, pid, sig);
	return ret;
#endif
	return (0);
}
