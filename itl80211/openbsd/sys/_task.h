//
//  _task.h
//  itlwm
//
//  Created by qcwap on 2020/3/1.
//  Copyright © 2020 钟先耀. All rights reserved.
//
/*
* Copyright (C) 2020  钟先耀
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*/

#ifndef _task_h
#define _task_h

#include <sys/queue.h>
#include <sys/_buf.h>
#include <stdint.h>

#include <IOKit/IOLocks.h>

/* Optional immutable metadata copied with one queue dispatch. Ordinary tasks
 * continue to use t_func/t_arg and task_add() without observing these fields. */
struct task_dispatch_context {
    uint64_t dispatch_id;
    uint32_t driver_generation;
    uint32_t fault_serial;
    uint32_t power_epoch;
    uint32_t power_flags;
    uint32_t dispatch_flags;
};

struct task;
typedef void (*task_dispatch_func)(void *,
    const struct task_dispatch_context *, const struct task *);

struct task {
    TAILQ_ENTRY(task) t_entry;
    void        (*t_func)(void *);
    void        *t_arg;
    unsigned int    t_flags;
    char name[256];
    task_dispatch_func t_dispatch_func;
    struct task_dispatch_context t_dispatch_context;
    uint64_t    t_dispatch_id;
    uint32_t    t_dispatch_state;
    uint32_t    t_dispatch_deferred;
    struct task *t_dispatch_source;
};

#define TASK_DISPATCH_RETIRED 1U

#define TASK_ONQUEUE        1
#define TASK_BARRIER        2

TAILQ_HEAD(task_list, task);

#define TASKQ_MPSAFE        (1 << 0)

#define TASK_INITIALIZER(_f, _a)  {{ NULL, NULL }, (_f), (_a), 0 }

#define task_pending(_t)    ((_t)->t_flags & TASK_ONQUEUE)

extern struct taskq *const systq;

void taskq_init();
struct taskq    *taskq_create(const char *, unsigned int, int, unsigned int);
void         taskq_destroy(struct taskq *);
void         taskq_barrier(struct taskq *);

void         taskq_del_barrier(struct taskq *, struct task *);

/* Nonblocking pause helpers for a queue with one or more workers. */
enum taskq_pause_diag_reason {
    TASKQ_PAUSE_DIAG_NONE = 0,
    TASKQ_PAUSE_DIAG_INVALID = 1,
    TASKQ_PAUSE_DIAG_LOCK_BUSY = 2,
    TASKQ_PAUSE_DIAG_DESTROYED = 3,
    TASKQ_PAUSE_DIAG_PAUSED = 4,
    TASKQ_PAUSE_DIAG_ACTIVE = 5
};

/* active is UINT32_MAX when lock acquisition failed and cannot be read safely. */
struct taskq_pause_diagnostics {
    uint32_t reason;
    uint32_t active;
};

int          taskq_try_pause(struct taskq *);
int          taskq_try_pause_with_diagnostics(
    struct taskq *, struct taskq_pause_diagnostics *);
void         taskq_resume(struct taskq *);
/* Acquire the queue mutex only when the queue is not paused; leave it held. */
int          taskq_enter_unpaused(struct taskq *);
void         taskq_leave(struct taskq *);

void         task_set(struct task *, void (*)(void *), void *, const char *);
int         task_add(struct taskq *, struct task *);
/* Tagged add is used by selected Tahoe init dispatches. Repeated queued calls
 * coalesce into one pending task and replace its context under the queue lock. */
int         task_add_tagged(struct taskq *, struct task *, task_dispatch_func,
                            const struct task_dispatch_context *);
int         task_defer_tagged(struct taskq *, const struct task *,
                              task_dispatch_func,
                              const struct task_dispatch_context *);
int         taskq_flush_deferred_tagged(struct taskq *, struct task *);
void        taskq_complete_work(struct taskq *, const struct task *);
int         task_dispatch_is_current(const struct task *, uint64_t);
int         task_del(struct taskq *, struct task *);

#endif /* _task_h */
