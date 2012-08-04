#include "config.h"

#include <sys/types.h>
#include "ptrace.h"
#include "proc.h"
#include "common.h"

void *
get_instruction_pointer(Process *proc) {
	proc_archdep *a = (proc_archdep *) (proc->arch_ptr);
	if (a->valid)
		return (void *)a->regs.r_rip;
	return (void *)-1;
}

void
set_instruction_pointer(Process *proc, void *addr) {
	proc_archdep *a = (proc_archdep *) (proc->arch_ptr);
	if (a->valid) {
		a->regs.r_rip = (long)addr;
		ptrace(PT_SETREGS, proc->pid, (caddr_t)&a->regs, 0);
	}
}

void *
get_stack_pointer(Process *proc) {
	proc_archdep *a = (proc_archdep *) (proc->arch_ptr);
	if (a->valid)
		return (void *)a->regs.r_rsp;
	return (void *)-1;
}

void *
get_return_addr(Process *proc, void *stack_pointer) {
	unsigned long int ret;
	ret = ptrace(PT_READ_I, proc->pid, stack_pointer, 0);
	return (void *)ret;
}

/* XXX not used */
void
set_return_addr(Process *proc, void *addr) {
	ptrace(PT_WRITE_I, proc->pid, proc->stack_pointer, (long)addr);
}
