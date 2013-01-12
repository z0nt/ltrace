/*
 * This file is part of ltrace.
 * Copyright (C) 2011 Petr Machata, Red Hat Inc.
 * Copyright (C) 2006 Ian Wienand
 * Copyright (C) 2002,2008,2009 Juan Cespedes
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

#include <sys/ptrace.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "common.h"
#include "backend.h"
#include "sysdep.h"
#include "breakpoint.h"
#include "proc.h"
#include "library.h"

void
arch_enable_breakpoint(pid_t pid, struct breakpoint *sbp)
{
	static unsigned char break_insn[] = BREAKPOINT_VALUE;
	struct ptrace_io_desc io;

	debug(DEBUG_PROCESS,
	      "arch_enable_breakpoint: pid=%d, addr=%p, symbol=%s",
	      pid, sbp->addr, breakpoint_name(sbp));

#ifdef HAVE_VALGRIND
	bzero(&io, sizeof(io));
#endif
	io.piod_op = PIOD_READ_I;
	io.piod_offs = sbp->addr;
	io.piod_addr = &sbp->orig_value;
	io.piod_len = sizeof(sbp->orig_value);
	if (ptrace(PT_IO, pid, (caddr_t)&io, 0) == -1) {
		fprintf(stderr, "enable_breakpoint: read"
			" pid=%d, addr=%p, symbol=%s: %s\n",
			pid, sbp->addr, breakpoint_name(sbp),
			strerror(errno));
		return;
	}
	io.piod_op = PIOD_WRITE_I;
	io.piod_offs = sbp->addr;
	io.piod_addr = &break_insn;
	io.piod_len = sizeof(break_insn);
	if (ptrace(PT_IO, pid, (caddr_t)&io, 0) == -1) {
		fprintf(stderr, "enable_breakpoint"
			" pid=%d, addr=%p, symbol=%s: %s\n",
			pid, sbp->addr, breakpoint_name(sbp),
			strerror(errno));
		return;
	}
}

void
enable_breakpoint(struct process *proc, struct breakpoint *sbp)
{
	debug(DEBUG_PROCESS, "enable_breakpoint: pid=%d, addr=%p, symbol=%s",
	      proc->pid, sbp->addr, breakpoint_name(sbp));
	arch_enable_breakpoint(proc->pid, sbp);
}

void
arch_disable_breakpoint(pid_t pid, struct breakpoint *sbp)
{
	struct ptrace_io_desc io;

	debug(DEBUG_PROCESS,
	      "arch_disable_breakpoint: pid=%d, addr=%p, symbol=%s",
	      pid, sbp->addr, breakpoint_name(sbp));

#ifdef HAVE_VALGRIND
	bzero(&io, sizeof(io));
#endif
	io.piod_op = PIOD_WRITE_I;
	io.piod_offs = sbp->addr;
	io.piod_addr = &sbp->orig_value;
	io.piod_len = sizeof(sbp->orig_value);
	if (ptrace(PT_IO, pid, (caddr_t)&io, 0) == -1) {
		fprintf(stderr,
			"disable_breakpoint pid=%d, addr=%p: %s\n",
			pid, sbp->addr, strerror(errno));
		return;
	}
}

void
disable_breakpoint(struct process *proc, struct breakpoint *sbp)
{
	debug(DEBUG_PROCESS, "disable_breakpoint: pid=%d, addr=%p, symbol=%s",
	      proc->pid, sbp->addr, breakpoint_name(sbp));
	arch_disable_breakpoint(proc->pid, sbp);
}
