/*
 * This file is part of ltrace.
 * Copyright (C) 2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 1998,2002,2004,2008,2009 Juan Cespedes
 * Copyright (C) 2006 Ian Wienand
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include "config.h"

#include <sys/types.h>
#include <sys/ptrace.h>
#include <machine/reg.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "backend.h"
#include "proc.h"

void *
get_instruction_pointer(struct process *proc)
{
	if (proc->os.valid_regs)
#ifdef __x86_64__
		return (void *)proc->os.regs.r_rip;
#else
		return (void *)proc->os.regs.r_eip;
#endif
	return (void *)-1;
}

void
set_instruction_pointer(struct process *proc, arch_addr_t addr)
{
	if (proc->os.valid_regs) {
#ifdef __x86_64__
		proc->os.regs.r_rip = (long)addr;
#else
		proc->os.regs.r_eip = (long)addr;
#endif
		ptrace(PT_SETREGS, proc->pid, (caddr_t)&proc->os.regs, 0);
	}
}

void *
get_stack_pointer(struct process *proc)
{
	if (proc->os.valid_regs)
#ifdef __x86_64__
		return (void *)proc->os.regs.r_rsp;
#else
		return (void *)proc->os.regs.r_esp;
#endif
	return (void *)-1;
}

void *
get_return_addr(struct process *proc, void *sp)
{
	unsigned long ret;
	struct ptrace_io_desc io;

#ifdef HAVE_VALGRIND
	bzero(&io, sizeof(io));
#endif
	io.piod_op = PIOD_READ_I;
	io.piod_offs = sp;
	io.piod_addr = &ret;
	io.piod_len = sizeof(ret);
	if (ptrace(PT_IO, proc->pid, (caddr_t)&io, 0) == -1)
		return (void *)-1;
	if (proc->e_machine == EM_386)
		ret &= 0xffffffff;
	return (void *)ret;
}

void
set_return_addr(struct process *proc, void *addr)
{
	struct ptrace_io_desc io;

#ifdef HAVE_VALGRIND
	bzero(&io, sizeof(io));
#endif
	io.piod_op = PIOD_WRITE_I;
	io.piod_offs = proc->stack_pointer;
	io.piod_addr = &addr;
	io.piod_len = sizeof(addr);
	ptrace(PT_IO, proc->pid, (caddr_t)&io, 0);
}
