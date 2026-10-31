//
//  _task.cpp
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

#include <sys/_task.h>
#include <sys/proc.h>
#include <sys/errno.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOCommandGate.h>

enum ETQ_STATE {
    TQ_S_CREATED,
    TQ_S_RUNNING,
    TQ_S_DESTROYED
};

struct taskq {
    enum ETQ_STATE       tq_state;
    unsigned int         tq_running;
    unsigned int         tq_waiting;
    unsigned int         tq_nthreads;
    unsigned int         tq_flags;
    const char        *tq_name;

    IORecursiveLock *tq_mtx;
    struct task_list     tq_worklist;
    unsigned int         tq_active;
    int                  tq_paused;
};

static const char taskq_sys_name[] = "systq";

struct taskq taskq_sys = {
    TQ_S_CREATED,
    0,
    0,
    1,
    0,
    taskq_sys_name,
};

struct taskq *const systq = &taskq_sys;

int
taskq_next_work(struct taskq *tq, struct task *work)
{
    struct task *next;
    
    //    IOLog("itlwm: taskq %s lock\n", __FUNCTION__);
    IORecursiveLockLock(tq->tq_mtx);
    
    for (;;) {
        next = TAILQ_FIRST(&tq->tq_worklist);
        if (tq->tq_state != TQ_S_RUNNING) {
            IORecursiveLockUnlock(tq->tq_mtx);
            return (0);
        }
        if (!tq->tq_paused && next != NULL)
            break;
        IORecursiveLockSleep(tq->tq_mtx, tq, THREAD_INTERRUPTIBLE);
    }

    TAILQ_REMOVE(&tq->tq_worklist, next, t_entry);
    CLR(next->t_flags, TASK_ONQUEUE);

    *work = *next; /* copy to caller to avoid races */
    work->t_dispatch_source = next;
    /* Count active before releasing the same lock used by try_pause(). */
    tq->tq_active++;

    next = TAILQ_FIRST(&tq->tq_worklist);
    IORecursiveLockUnlock(tq->tq_mtx);
//    IOLog("itlwm: taskq %s unlock\n", __FUNCTION__);

    if (next != NULL && tq->tq_nthreads > 1)
        IORecursiveLockWakeup(tq->tq_mtx, tq, true);

    return (1);
}

static void
taskq_work_done(struct taskq *tq)
{
    IORecursiveLockLock(tq->tq_mtx);
    if (tq->tq_active > 0)
        tq->tq_active--;
    if (tq->tq_active == 0)
        IORecursiveLockWakeup(tq->tq_mtx, tq, true);
    IORecursiveLockUnlock(tq->tq_mtx);
}

static void
taskq_run_work(const struct task *work)
{
    if (work->t_dispatch_func != NULL)
        (*work->t_dispatch_func)(work->t_arg, &work->t_dispatch_context,
                                 work->t_dispatch_source);
    else
        (*work->t_func)(work->t_arg);
}

void
taskq_thread(void *xtq)
{
    struct taskq *tq = (struct taskq *)xtq;
    struct task work;
    int last;

//    if (ISSET(tq->tq_flags, TASKQ_MPSAFE))
//        KERNEL_UNLOCK();

//    WITNESS_CHECKORDER(&tq->tq_lock_object, LOP_NEWORDER, NULL);
    
    IOLog("itlwm: taskq %s schedule task\n", __FUNCTION__);

    while (taskq_next_work(tq, &work)) {
//        WITNESS_LOCK(&tq->tq_lock_object, 0);
//        IOLog("itlwm: taskq worker thread=%lld work=%s\n", thread_tid(current_thread()), work.name);
        taskq_run_work(&work);
        taskq_complete_work(tq, &work);
        taskq_work_done(tq);
//        IOLog("itlwm: taskq worker thread=%lld work=%s done", thread_tid(current_thread()), work.name);
//        WITNESS_UNLOCK(&tq->tq_lock_object, 0);
//        sched_pause(yield);
        IOSleep(1);
    }
    
    IOLog("itlwm: taskq %s schedule task done\n", __FUNCTION__);

    IORecursiveLockLock(tq->tq_mtx);
    last = (--tq->tq_running == 0);
    IORecursiveLockUnlock(tq->tq_mtx);

//    if (ISSET(tq->tq_flags, TASKQ_MPSAFE))
//        KERNEL_LOCK();

    if (last) {
        IOLog("itlwm: taskq %s schedule task wakeup\n", __FUNCTION__);
        IORecursiveLockWakeup(tq->tq_mtx, tq, false);
    }

//    kthread_exit(0);
    thread_terminate(current_thread());
}

void taskq_create_thread(void *arg)
{
    struct taskq *tq = (struct taskq *)arg;
    int rv;
    IOLog("itlwm: taskq %s lock\n", __FUNCTION__);
    IORecursiveLockLock(tq->tq_mtx);
    switch (tq->tq_state) {
        case TQ_S_DESTROYED:
            IOLog("itlwm: taskq %s unlock\n", __FUNCTION__);
            IORecursiveLockUnlock(tq->tq_mtx);
            if (tq != systq) {
                IORecursiveLockFree(tq->tq_mtx);
                IOFree(tq, sizeof(*tq));
            }
            return;

        case TQ_S_CREATED:
            tq->tq_state = TQ_S_RUNNING;
            break;

        default:
            IOLog("itlwm: unexpected %s tq state %u", tq->tq_name, tq->tq_state);
            IORecursiveLockUnlock(tq->tq_mtx);
            if (tq != systq) {
                IORecursiveLockFree(tq->tq_mtx);
                IOFree(tq, sizeof(*tq));
            }
            return;
    }

    do {
        tq->tq_running++;
        IOLog("itlwm: taskq %s unlock\n", __FUNCTION__);
        IORecursiveLockUnlock(tq->tq_mtx);

        thread_t new_thread;
        rv = kernel_thread_start((thread_continue_t)taskq_thread, tq, &new_thread);
        thread_deallocate(new_thread);

        IOLog("itlwm: taskq %s lock\n", __FUNCTION__);
        IORecursiveLockLock(tq->tq_mtx);
        if (rv != KERN_SUCCESS) {
            IOLog("itlwm: tasq unable to create thread for \"%s\" taskq\n",
                   tq->tq_name);

            tq->tq_running--;
            /* could have been destroyed during kthread_create */
            if (tq->tq_state == TQ_S_DESTROYED &&
                tq->tq_running == 0)
                IORecursiveLockWakeup(tq->tq_mtx, tq, false);
            break;
        }
    } while (tq->tq_running < tq->tq_nthreads);
    
    IOLog("itlwm: taskq %s unlock\n", __FUNCTION__);
    IORecursiveLockUnlock(tq->tq_mtx);
}

void
taskq_init(void)
{
    systq->tq_mtx = IORecursiveLockAlloc();
    TAILQ_INIT(&systq->tq_worklist);
    thread_t new_thread;
    kernel_thread_start((thread_continue_t)taskq_create_thread, systq, &new_thread);
    thread_deallocate(new_thread);
}

struct taskq *
taskq_create(const char *name, unsigned int nthreads, int ipl,
             unsigned int flags)
{
    struct taskq *tq;

    tq = (struct taskq *)IOMalloc(sizeof(*tq));
    if (tq == NULL)
        return (NULL);

    tq->tq_state = TQ_S_CREATED;
    tq->tq_running = 0;
    tq->tq_waiting = 0;
    tq->tq_active = 0;
    tq->tq_paused = 0;
    tq->tq_nthreads = nthreads;
    tq->tq_name = name;
    tq->tq_flags = flags;
    tq->tq_mtx = IORecursiveLockAlloc();

    //    mtx_init_flags(&tq->tq_mtx, ipl, name, 0);
    TAILQ_INIT(&tq->tq_worklist);
    thread_t new_thread;
    /* try to create a thread to guarantee that tasks will be serviced */
    kernel_thread_start((thread_continue_t)taskq_create_thread, tq, &new_thread);
    thread_deallocate(new_thread);
    return (tq);
}

void
taskq_destroy(struct taskq *tq)
{
    if (!tq || !tq->tq_mtx) {
        return;
    }
    IORecursiveLockLock(tq->tq_mtx);
    switch (tq->tq_state) {
        case TQ_S_CREATED:
            /* tq is still referenced by taskq_create_thread */
            tq->tq_state = TQ_S_DESTROYED;
            IORecursiveLockUnlock(tq->tq_mtx);
            return;

        case TQ_S_RUNNING:
            tq->tq_state = TQ_S_DESTROYED;
            break;

        default:
            IOLog("itlwm: unexpected %s tq state %u", tq->tq_name, tq->tq_state);
            tq->tq_state = TQ_S_DESTROYED;
            IORecursiveLockUnlock(tq->tq_mtx);
            return;
    }

    while (tq->tq_running > 0) {
        IORecursiveLockWakeup(tq->tq_mtx, tq, false);
        IORecursiveLockSleep(tq->tq_mtx, tq, THREAD_INTERRUPTIBLE);
    }

    IORecursiveLockUnlock(tq->tq_mtx);
    IORecursiveLockFree(tq->tq_mtx);
    if (tq != systq) {
        IOFree(tq, sizeof(*tq));
    }
    
}

void
task_set(struct task *t, void (*fn)(void *), void *arg, const char *name)
{
    t->t_func = fn;
    t->t_arg = arg;
    t->t_flags = 0;
    memcpy(t->name, name, sizeof(t->name));
    t->t_dispatch_func = NULL;
    memset(&t->t_dispatch_context, 0, sizeof(t->t_dispatch_context));
    __atomic_store_n(&t->t_dispatch_state, TASK_DISPATCH_RETIRED,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&t->t_dispatch_id, UINT64_C(0), __ATOMIC_RELEASE);
    t->t_dispatch_deferred = 0;
    t->t_dispatch_source = NULL;
}

int
task_add(struct taskq *tq, struct task *w)
{
    int rv = 0;
//    IOLog("itlwm: taskq task_add %s thread: %lld\n", w->name, thread_tid(current_thread()));
    
    if (ISSET(w->t_flags, TASK_ONQUEUE))
        return (0);

    IORecursiveLockLock(tq->tq_mtx);
    if (tq->tq_state == TQ_S_DESTROYED) {
        IORecursiveLockUnlock(tq->tq_mtx);
        return (0);
    }
    /* A paused queue accepts no new work until its owner resumes it. */
    if (tq->tq_paused) {
        IORecursiveLockUnlock(tq->tq_mtx);
        return (0);
    }
    if (ISSET(w->t_flags, TASK_ONQUEUE)) {
//        IOLog("itlwm: taskq task_add %s is already on queue thread: %lld\n", w->name, thread_tid(current_thread()));
        IORecursiveLockUnlock(tq->tq_mtx);
        return (0);
    }
    if (!ISSET(w->t_flags, TASK_ONQUEUE)) {
//        IOLog("itlwm: taskq task_add %s add to queue thread: %lld\n", w->name, thread_tid(current_thread()));
        rv = 1;
        /* A plain task_add remains an untagged, one-argument callback. */
        w->t_dispatch_func = NULL;
        memset(&w->t_dispatch_context, 0, sizeof(w->t_dispatch_context));
        __atomic_store_n(&w->t_dispatch_state, TASK_DISPATCH_RETIRED,
                         __ATOMIC_RELEASE);
        __atomic_store_n(&w->t_dispatch_id, UINT64_C(0), __ATOMIC_RELEASE);
        w->t_dispatch_deferred = 0;
        w->t_dispatch_source = NULL;
        SET(w->t_flags, TASK_ONQUEUE);
        TAILQ_INSERT_TAIL(&tq->tq_worklist, w, t_entry);
    }
    IORecursiveLockUnlock(tq->tq_mtx);

    if (rv)
        IORecursiveLockWakeup(tq->tq_mtx, tq, true);

    return (rv);
}

int
task_add_tagged(struct taskq *tq, struct task *w,
                task_dispatch_func fn,
                const struct task_dispatch_context *context)
{
    if (tq == NULL || w == NULL || fn == NULL || context == NULL)
        return (-1);
    if (context->dispatch_id == 0)
        return (-1);

    IORecursiveLockLock(tq->tq_mtx);
    if (tq->tq_state == TQ_S_DESTROYED || tq->tq_paused) {
        IORecursiveLockUnlock(tq->tq_mtx);
        return (-1);
    }

    const uint64_t currentId = __atomic_load_n(&w->t_dispatch_id,
                                               __ATOMIC_ACQUIRE);
    const uint32_t currentState = __atomic_load_n(&w->t_dispatch_state,
                                                 __ATOMIC_ACQUIRE);
    if (currentId != 0 && context->dispatch_id != currentId) {
        const uint64_t distance = context->dispatch_id - currentId;
        if (distance >= (UINT64_C(1) << 63)) {
            IORecursiveLockUnlock(tq->tq_mtx);
            return (0); /* A late producer cannot replace a newer dispatch. */
        }
    } else if (context->dispatch_id == currentId &&
               (currentState & TASK_DISPATCH_RETIRED)) {
        IORecursiveLockUnlock(tq->tq_mtx);
        return (0); /* Completion/cancellation retires this exact identity. */
    } else if (context->dispatch_id == currentId) {
        /* Context is immutable for one identity. A same-id add cannot revive
         * or rewrite a popped/deferred dispatch. */
        IORecursiveLockUnlock(tq->tq_mtx);
        return (0);
    }

    w->t_dispatch_func = fn;
    w->t_dispatch_context = *context;
    w->t_dispatch_deferred = 0;
    w->t_dispatch_source = NULL;
    __atomic_store_n(&w->t_dispatch_state, 0U, __ATOMIC_RELEASE);
    __atomic_store_n(&w->t_dispatch_id, context->dispatch_id,
                     __ATOMIC_RELEASE);
    if (ISSET(w->t_flags, TASK_ONQUEUE)) {
        /* This is still the same pending dispatch: replace its not-yet-popped
         * payload while holding the mutex that protects the queue snapshot. */
        IORecursiveLockUnlock(tq->tq_mtx);
        return (0);
    }

    SET(w->t_flags, TASK_ONQUEUE);
    TAILQ_INSERT_TAIL(&tq->tq_worklist, w, t_entry);
    IORecursiveLockUnlock(tq->tq_mtx);
    IORecursiveLockWakeup(tq->tq_mtx, tq, true);
    return (1);
}

int
task_defer_tagged(struct taskq *tq, const struct task *source,
                  task_dispatch_func fn,
                  const struct task_dispatch_context *context)
{
    if (tq == NULL || source == NULL || fn == NULL || context == NULL ||
        context->dispatch_id == 0)
        return (-1);

    struct task *w = const_cast<struct task *>(source);
    IORecursiveLockLock(tq->tq_mtx);
    if (tq->tq_state == TQ_S_DESTROYED || tq->tq_paused) {
        IORecursiveLockUnlock(tq->tq_mtx);
        return (-1);
    }

    const uint64_t currentId = __atomic_load_n(&w->t_dispatch_id,
                                               __ATOMIC_ACQUIRE);
    const uint32_t currentState = __atomic_load_n(&w->t_dispatch_state,
                                                 __ATOMIC_ACQUIRE);
    const struct task_dispatch_context *current = &w->t_dispatch_context;
    const bool sameContext = current->dispatch_id == context->dispatch_id &&
        current->driver_generation == context->driver_generation &&
        current->fault_serial == context->fault_serial &&
        current->power_epoch == context->power_epoch &&
        current->power_flags == context->power_flags &&
        current->dispatch_flags == context->dispatch_flags;
    if (currentId != context->dispatch_id ||
        (currentState & TASK_DISPATCH_RETIRED) ||
        w->t_dispatch_func != fn || !sameContext) {
        IORecursiveLockUnlock(tq->tq_mtx);
        return (0); /* Superseded work cannot be resurrected. */
    }
    if (ISSET(w->t_flags, TASK_ONQUEUE) || w->t_dispatch_deferred) {
        IORecursiveLockUnlock(tq->tq_mtx);
        return (0);
    }

    /* The source task remains the canonical immutable context slot. It is
     * parked until its lifecycle owner releases the fence and flushes it. */
    w->t_dispatch_deferred = 1;
    IORecursiveLockUnlock(tq->tq_mtx);
    return (1);
}

int
taskq_flush_deferred_tagged(struct taskq *tq, struct task *w)
{
    if (tq == NULL || w == NULL)
        return (-1);

    IORecursiveLockLock(tq->tq_mtx);
    if (!w->t_dispatch_deferred) {
        IORecursiveLockUnlock(tq->tq_mtx);
        return (0);
    }
    if (tq->tq_state == TQ_S_DESTROYED || tq->tq_paused) {
        IORecursiveLockUnlock(tq->tq_mtx);
        return (-1);
    }
    const uint32_t state = __atomic_load_n(&w->t_dispatch_state,
                                          __ATOMIC_ACQUIRE);
    if ((state & TASK_DISPATCH_RETIRED) || w->t_dispatch_func == NULL) {
        w->t_dispatch_deferred = 0;
        IORecursiveLockUnlock(tq->tq_mtx);
        return (0);
    }
    if (ISSET(w->t_flags, TASK_ONQUEUE)) {
        w->t_dispatch_deferred = 0;
        IORecursiveLockUnlock(tq->tq_mtx);
        return (0);
    }

    w->t_dispatch_deferred = 0;
    SET(w->t_flags, TASK_ONQUEUE);
    TAILQ_INSERT_TAIL(&tq->tq_worklist, w, t_entry);
    IORecursiveLockUnlock(tq->tq_mtx);
    IORecursiveLockWakeup(tq->tq_mtx, tq, true);
    return (1);
}

void
taskq_complete_work(struct taskq *tq, const struct task *work)
{
    if (tq == NULL || work == NULL || work->t_dispatch_func == NULL ||
        work->t_dispatch_source == NULL || work->t_dispatch_context.dispatch_id == 0)
        return;

    struct task *source = work->t_dispatch_source;
    IORecursiveLockLock(tq->tq_mtx);
    const uint64_t currentId = __atomic_load_n(&source->t_dispatch_id,
                                               __ATOMIC_ACQUIRE);
    const uint32_t state = __atomic_load_n(&source->t_dispatch_state,
                                          __ATOMIC_ACQUIRE);
    if (currentId == work->t_dispatch_context.dispatch_id &&
        !(state & TASK_DISPATCH_RETIRED) &&
        !ISSET(source->t_flags, TASK_ONQUEUE) &&
        !source->t_dispatch_deferred)
        __atomic_store_n(&source->t_dispatch_state, TASK_DISPATCH_RETIRED,
                         __ATOMIC_RELEASE);
    IORecursiveLockUnlock(tq->tq_mtx);
}

int
task_dispatch_is_current(const struct task *source, uint64_t dispatch_id)
{
    if (source == NULL || dispatch_id == 0)
        return (0);
    const uint64_t currentId = __atomic_load_n(&source->t_dispatch_id,
                                              __ATOMIC_ACQUIRE);
    const uint32_t state = __atomic_load_n(&source->t_dispatch_state,
                                           __ATOMIC_ACQUIRE);
    return (currentId == dispatch_id &&
            !(state & TASK_DISPATCH_RETIRED));
}

int
taskq_try_pause_with_diagnostics(struct taskq *tq,
                                 struct taskq_pause_diagnostics *diagnostics)
{
    if (diagnostics != NULL) {
        diagnostics->reason = TASKQ_PAUSE_DIAG_NONE;
        diagnostics->active = 0;
    }
    if (tq == NULL || tq->tq_mtx == NULL) {
        if (diagnostics != NULL)
            diagnostics->reason = TASKQ_PAUSE_DIAG_INVALID;
        return (ENXIO);
    }

    /* Stop is called from gate-sensitive paths; never wait for the mutex. */
    if (!IORecursiveLockTryLock(tq->tq_mtx)) {
        if (diagnostics != NULL) {
            diagnostics->reason = TASKQ_PAUSE_DIAG_LOCK_BUSY;
            diagnostics->active = UINT32_MAX;
        }
        return (EBUSY);
    }
    const unsigned int active = tq->tq_active;
    if (tq->tq_state == TQ_S_DESTROYED) {
        if (diagnostics != NULL) {
            diagnostics->reason = TASKQ_PAUSE_DIAG_DESTROYED;
            diagnostics->active = active;
        }
        IORecursiveLockUnlock(tq->tq_mtx);
        return (ENXIO);
    }
    if (tq->tq_paused) {
        if (diagnostics != NULL) {
            diagnostics->reason = TASKQ_PAUSE_DIAG_PAUSED;
            diagnostics->active = active;
        }
        IORecursiveLockUnlock(tq->tq_mtx);
        return (EBUSY);
    }
    if (active != 0) {
        if (diagnostics != NULL) {
            diagnostics->reason = TASKQ_PAUSE_DIAG_ACTIVE;
            diagnostics->active = active;
        }
        IORecursiveLockUnlock(tq->tq_mtx);
        return (EBUSY);
    }
    tq->tq_paused = 1;
    IORecursiveLockUnlock(tq->tq_mtx);
    return (0);
}

int
taskq_try_pause(struct taskq *tq)
{
    return (taskq_try_pause_with_diagnostics(tq, NULL));
}

void
taskq_resume(struct taskq *tq)
{
    if (tq == NULL || tq->tq_mtx == NULL)
        return;
    IORecursiveLockLock(tq->tq_mtx);
    tq->tq_paused = 0;
    IORecursiveLockWakeup(tq->tq_mtx, tq, true);
    IORecursiveLockUnlock(tq->tq_mtx);
}

int
taskq_enter_unpaused(struct taskq *tq)
{
    if (tq == NULL || tq->tq_mtx == NULL)
        return (ENXIO);
    IORecursiveLockLock(tq->tq_mtx);
    if (tq->tq_state == TQ_S_DESTROYED || tq->tq_paused) {
        int error = tq->tq_state == TQ_S_DESTROYED ? ENXIO : EBUSY;
        IORecursiveLockUnlock(tq->tq_mtx);
        return (error);
    }
    return (0); /* The caller owns tq_mtx until taskq_leave(). */
}

void
taskq_leave(struct taskq *tq)
{
    if (tq != NULL && tq->tq_mtx != NULL)
        IORecursiveLockUnlock(tq->tq_mtx);
}

int
task_del(struct taskq *tq, struct task *w)
{
    int rv = 0;
//    IOLog("itlwm: taskq task_del %s thread: %lld\n", w->name, thread_tid(current_thread()));

    if (tq == NULL || w == NULL)
        return (0);

    IORecursiveLockLock(tq->tq_mtx);
    if (ISSET(w->t_flags, TASK_ONQUEUE)) {
        rv = 1;
        CLR(w->t_flags, TASK_ONQUEUE);
        TAILQ_REMOVE(&tq->tq_worklist, w, t_entry);
    }
    if (w->t_dispatch_func != NULL ||
        __atomic_load_n(&w->t_dispatch_id, __ATOMIC_ACQUIRE) != 0) {
        __atomic_store_n(&w->t_dispatch_state, TASK_DISPATCH_RETIRED,
                         __ATOMIC_RELEASE);
        w->t_dispatch_deferred = 0;
    }
    IORecursiveLockUnlock(tq->tq_mtx);

    return (rv);
}
