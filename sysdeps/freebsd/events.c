/*
 * This file is part of ltrace.
 * Copyright (C) 2007,2011,2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 1998,2001,2004,2007,2008,2009 Juan Cespedes
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
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "backend.h"
#include "breakpoint.h"
#include "debug.h"
#include "events.h"
#include "proc.h"

static Event event;

/* A queue of events that we missed while enabling the
 * breakpoint in one of tasks.  */
static Event * delayed_events = NULL;
static Event * end_delayed_events = NULL;

static enum callback_status
first(struct process *proc, void *data)
{
	return CBS_STOP;
}

void
enque_event(Event * event)
{
	debug(DEBUG_FUNCTION, "%d: queuing event %d for later",
	      event->proc->pid, event->type);
	Event * ne = malloc(sizeof(*ne));
	if (ne == NULL) {
		fprintf(stderr, "event will be missed: %s\n", strerror(errno));
		return;
	}

	*ne = *event;
	ne->next = NULL;
	if (end_delayed_events == NULL) {
		assert(delayed_events == NULL);
		end_delayed_events = delayed_events = ne;
	}
	else {
		assert(delayed_events != NULL);
		end_delayed_events = end_delayed_events->next = ne;
	}
}

Event *
each_qd_event(enum ecb_status (*pred)(Event *, void *), void * data)
{
	Event * prev = delayed_events;
	Event * event;
	for (event = prev; event != NULL; ) {
		switch ((*pred)(event, data)) {
		case ECB_CONT:
			prev = event;
			event = event->next;
			continue;

		case ECB_DEQUE:
			debug(DEBUG_FUNCTION, "dequeuing event %d for %d",
			      event->type,
			      event->proc != NULL ? event->proc->pid : -1);
			/*
			printf("dequeuing event %d for %d\n", event->type,
			       event->proc != NULL ? event->proc->pid : -1) ;
			*/
			if (end_delayed_events == event)
				end_delayed_events = prev;
			if (delayed_events == event)
				delayed_events = event->next;
			else
				prev->next = event->next;
			if (delayed_events == NULL)
				end_delayed_events = NULL;
			/* fall-through */

		case ECB_YIELD:
			return event;
		}
	}

	return NULL;
}

static enum ecb_status
event_process_not_reenabling(Event * event, void * data)
{
	if (event->proc == NULL
	    || event->proc->leader == NULL
	    || event->proc->leader->event_handler == NULL)
		return ECB_DEQUE;
	else
		return ECB_CONT;
}

static Event *
next_qd_event(void)
{
	return each_qd_event(&event_process_not_reenabling, NULL);
}

int in_waitpid = 0;

Event *
next_event(void)
{
	struct ptrace_lwpinfo *lwpinfo;
	siginfo_t *siginfo;
	pid_t pid;
	int status;
	int tmp;
	int stop_signal;

	debug(DEBUG_FUNCTION, "next_event()");
	Event * ev;
	if ((ev = next_qd_event()) != NULL) {
		event = *ev;
		free(ev);
		return &event;
	}

	if (!each_process(NULL, &first, NULL)) {
		debug(DEBUG_EVENT, "event: No more traced programs: exiting");
		exit(0);
	}

	in_waitpid = 1;
	pid = waitpid(-1, &status, 0);
	in_waitpid = 0;

	if (pid == -1) {
		if (errno == ECHILD) {
			debug(DEBUG_EVENT, "event: No more traced programs: exiting");
			exit(0);
		} else if (errno == EINTR) {
			debug(DEBUG_EVENT, "event: none (wait received EINTR?)");
			event.type = EVENT_NONE;
			return &event;
		}
		perror("wait");
		exit(1);
	}
	event.proc = pid2proc(pid);
	if (!event.proc || event.proc->state == STATE_BEING_CREATED) {
		struct ptrace_lwpinfo newinfo;
#ifdef HAVE_VALGRIND
		bzero(&newinfo, sizeof(newinfo));
#endif
		if (ptrace(PT_LWPINFO, pid, (caddr_t)&newinfo, sizeof(newinfo)) == 0 &&
		    (newinfo.pl_flags & PL_FLAG_CHILD) != 0) {
			event.type = EVENT_NEW;
			event.e_un.newpid = pid;
			debug(DEBUG_EVENT, "event: NEW: pid=%d", pid);
			return &event;
		}
		if (process_status(pid) == PS_TRACING_STOP)
			continue_process(pid);
		event.type = EVENT_NONE;
		debug(DEBUG_EVENT, "event: NONE: pid=%d", pid);
		return &event;
	}
	get_arch_dep(event.proc);
	debug(3, "event from pid %u", pid);
	lwpinfo = &event.proc->os.lwpinfo;
	siginfo = &lwpinfo->pl_siginfo;

	/* The process should be stopped after the waitpid call.  But
	 * when the whole thread group is terminated, we see
	 * individual tasks spontaneously transitioning from 't' to
	 * 'R' and 'Z'.  Calls to ptrace fail and /proc/pid/status may
	 * not even be available anymore, so we can't check in
	 * advance.  So we just drop the error checking around ptrace
	 * calls.  We check for termination ex post when it fails,
	 * suppress the event, and let the event loop collect the
	 * termination in the next iteration.  */
#define CHECK_PROCESS_TERMINATED					\
	do {								\
		int errno_save = errno;					\
		switch (process_stopped(pid))				\
		case 0:							\
		case -1: {						\
			debug(DEBUG_EVENT,				\
			      "process not stopped, is it terminating?"); \
			event.type = EVENT_NONE;			\
			continue_process(event.proc->pid);		\
			return &event;					\
		}							\
		errno = errno_save;					\
	} while (0)

	event.proc->instruction_pointer = (void *)(uintptr_t)-1;

	/* Check for task termination now, before we have a need to
	 * call CHECK_PROCESS_TERMINATED later.  That would suppress
	 * the event that we are processing.  */
	if (WIFSIGNALED(status)) {
		event.type = EVENT_EXIT_SIGNAL;
		event.e_un.signum = WTERMSIG(status);
		debug(DEBUG_EVENT, "event: EXIT_SIGNAL: pid=%d, signum=%d", pid, event.e_un.signum);
		return &event;
	}
	if (WIFEXITED(status)) {
		event.type = EVENT_EXIT;
		event.e_un.ret_val = WEXITSTATUS(status);
		debug(DEBUG_EVENT, "event: EXIT: pid=%d, status=%d", pid, event.e_un.ret_val);
		return &event;
	}

	event.proc->instruction_pointer = get_instruction_pointer(event.proc);
	if (event.proc->instruction_pointer == (void *)(uintptr_t)-1) {
		CHECK_PROCESS_TERMINATED;
		if (errno != 0)
			perror("get_instruction_pointer");
	}

	if (WIFSTOPPED(status)) {
		if (lwpinfo->pl_flags & PL_FLAG_FORKED) {
			event.type = is_vfork(pid, lwpinfo->pl_child_pid) ?
			    EVENT_VFORK : EVENT_CLONE;
			event.e_un.newpid = lwpinfo->pl_child_pid;
			debug(DEBUG_EVENT, "event: FORK: pid=%d, newpid=%d",
			      pid, event.e_un.newpid);
			return &event;
		}
		if (lwpinfo->pl_flags & PL_FLAG_EXEC) {
			event.type = EVENT_EXEC;
			debug(DEBUG_EVENT, "event: EXEC: pid=%d", pid);
			return &event;
		}
	}
	switch (syscall_p(event.proc, status, &tmp)) {
	case 1:
		event.type = EVENT_SYSCALL;
		event.e_un.sysnum = tmp;
		debug(DEBUG_EVENT, "event: SYSCALL: pid=%d, sysnum=%d", pid, tmp);
		return &event;
	case 2:
		event.type = EVENT_SYSRET;
		event.e_un.sysnum = tmp;
		debug(DEBUG_EVENT, "event: SYSRET: pid=%d, sysnum=%d", pid, tmp);
		return &event;
	}
	if (!WIFSTOPPED(status)) {
		/* should never happen */
		event.type = EVENT_NONE;
		debug(DEBUG_EVENT, "event: NONE: pid=%d (wait error?)", pid);
		return &event;
	}

	stop_signal = WSTOPSIG(status);
	if (stop_signal != SIGTRAP) {
		event.type = EVENT_SIGNAL;
		event.e_un.signum = stop_signal;
		debug(DEBUG_EVENT, "event: SIGNAL: pid=%d, signum=%d", pid, stop_signal);
		return &event;
	}

	if (lwpinfo->pl_event == PL_EVENT_SIGNAL &&
	    (lwpinfo->pl_flags & PL_FLAG_SI) &&
	    siginfo->si_signo == SIGTRAP &&
	    (siginfo->si_code == TRAP_BRKPT ||
	    siginfo->si_code == TRAP_TRACE)) {
		event.type = EVENT_BREAKPOINT;
		event.e_un.brk_addr = event.proc->instruction_pointer - DECR_PC_AFTER_BREAK;
		debug(DEBUG_EVENT, "event: BREAKPOINT: pid=%d, addr=%p", pid, event.e_un.brk_addr);
		return &event;
	}

	/* unknown event */
	if (process_status(pid) == PS_TRACING_STOP)
		continue_process(pid);
	event.type = EVENT_NONE;
	debug(DEBUG_EVENT, "event: NONE: pid=%d", pid);
	return &event;
}

static enum ecb_status
event_for_proc(struct Event *event, void *data)
{
	if (event->proc == data)
		return ECB_DEQUE;
	else
		return ECB_CONT;
}

void
delete_events_for(struct process *proc)
{
	struct Event *event;
	while ((event = each_qd_event(&event_for_proc, proc)) != NULL)
		free(event);
}
