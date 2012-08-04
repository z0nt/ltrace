#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "common.h"
#include "ptrace.h"
#include "proc.h"

void
get_arch_dep(Process *proc) {
	proc_archdep *a;

	if (!proc->arch_ptr)
		proc->arch_ptr = (void *)malloc(sizeof(proc_archdep));

	a = (proc_archdep *) (proc->arch_ptr);
	a->valid = (ptrace(PT_GETREGS, proc->pid, (caddr_t)&a->regs, 0) >= 0);
}

/* Returns 1 if syscall, 2 if sysret, 0 otherwise.
 */
int
syscall_p(struct Process *proc, int status, int *sysnum)
{
	struct ptrace_lwpinfo info;

	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
		*sysnum = ((proc_archdep *) proc->arch_ptr)->regs.r_rax;
		debug(DEBUG_FUNCTION, "sysnum=%d %p %d\n", *sysnum,
		    get_instruction_pointer(proc), errno);
		ptrace(PT_LWPINFO, proc->pid, (caddr_t)&info, sizeof(info));
		if (info.pl_flags & PL_FLAG_SCE)
			return (1);
		else if (info.pl_flags & PL_FLAG_SCX)
			return (2);
	}

	return (0);
}

long
gimme_arg(enum tof type, Process *proc, int arg_num, arg_type_info *info) {
	proc_archdep *a = (proc_archdep *) proc->arch_ptr;
	if (!a->valid) {
		fprintf(stderr, "Could not get child registers\n");
		exit(1);
	}
	if (arg_num == -1)	/* return value */
		return a->regs.r_rax;

	if (type == LT_TOF_FUNCTION || type == LT_TOF_SYSCALL || arg_num >= 6) {
		switch (arg_num) {
		case 0:
			return a->regs.r_rdi;
		case 1:
			return a->regs.r_rsi;
		case 2:
			return a->regs.r_rdx;
		case 3:
			return a->regs.r_rcx;
		case 4:
			return a->regs.r_r8;
		case 5:
			return a->regs.r_r9;
		default:
			fprintf(stderr, "gimme_arg: not implemented\n");
			exit(1);
			/* FIXME: zont
			return ptrace(PTRACE_PEEKTEXT, proc->pid,
			    proc->stack_pointer + 8 * (arg_num - 6 + 1), 0);
			*/
		}
	} else if (type == LT_TOF_FUNCTIONR)
		return a->func_arg[arg_num];
	else if (type == LT_TOF_SYSCALLR)
		return a->sysc_arg[arg_num];
	else {
		fprintf(stderr, "gimme_arg called with wrong arguments\n");
		exit(1);
	}
	return 0;
}

void
save_register_args(enum tof type, Process *proc) {
	proc_archdep *a = (proc_archdep *) proc->arch_ptr;
	if (a->valid) {
		if (type == LT_TOF_FUNCTION)
			memcpy(a->func_arg, &a->regs.r_rdi, sizeof(a->func_arg));
		else
			memcpy(a->sysc_arg, &a->regs.r_rdi, sizeof(a->sysc_arg));
	}
}
