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
	struct ptrace_io_desc io;
	io.piod_op = PIOD_READ_I;
	io.piod_offs = stack_pointer;
	io.piod_addr = &ret;
	io.piod_len = sizeof(ret);
	if (ptrace(PT_IO, proc->pid, (caddr_t)&io, 0) == 0)
		return (void *)ret;
	return (void *)-1;
}

/* XXX not used */
void
set_return_addr(Process *proc, void *addr) {
	ptrace(PT_WRITE_I, proc->pid, proc->stack_pointer, (long)addr);
}
