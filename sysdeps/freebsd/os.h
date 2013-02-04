/*
 * This file is part of ltrace.
 * Copyright (C) 2012 Petr Machata
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

#include <sys/queue.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <machine/reg.h>

int is_vfork(pid_t pid1, pid_t pid2);

struct threadinfo
{
	SLIST_ENTRY(threadinfo) next;
	lwpid_t tid;
	int valid_regs;
	struct reg regs;
	int onstep;
	struct process *proc;
	int saved;
	/* from struct process */
	size_t callstack_depth;
	struct callstack_element *callstack;
	struct event_handler *event_handler;
};

#define OS_HAVE_PROCESS_DATA
struct os_process_data {
	arch_addr_t debug_addr;
	int debug_state;
	struct ptrace_lwpinfo lwpinfo;
	SLIST_HEAD(, threadinfo) threads;
};

struct threadinfo *curthread;
