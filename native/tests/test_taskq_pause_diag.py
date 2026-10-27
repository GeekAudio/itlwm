#!/usr/bin/env python3
"""Compile the production taskq pause helpers against a nonblocking lock shim."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itl80211/openbsd/sys/_task.cpp"


def production_function(source: str, marker: str) -> str:
    marker_at = source.index(marker)
    start = source.rfind("\nint\n", 0, marker_at) + 1
    brace = source.index("{", marker_at)
    depth = 0
    i = brace
    state = "code"
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line_comment"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block_comment"
                i += 2
                continue
            if ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return source[start:i + 1]
        elif state == "line_comment":
            if ch == "\n":
                state = "code"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
                continue
        elif state in ("string", "char"):
            if ch == "\\":
                i += 2
                continue
            if (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                state = "code"
        i += 1
    raise RuntimeError(f"unterminated production function: {marker}")


source = SOURCE.read_text()
methods = [
    production_function(source, "taskq_try_pause_with_diagnostics("),
    production_function(source, "taskq_try_pause(struct taskq *tq)"),
    production_function(source, "task_add(struct taskq *tq, struct task *w)"),
]

HARNESS = r'''
#include <assert.h>
#include <stdint.h>
#include <cstdio>

constexpr int EBUSY = 16;
constexpr int ENXIO = 6;
enum taskq_state { TQ_S_CREATED, TQ_S_RUNNING, TQ_S_DESTROYED };
enum taskq_pause_diag_reason {
 TASKQ_PAUSE_DIAG_NONE=0, TASKQ_PAUSE_DIAG_INVALID=1,
 TASKQ_PAUSE_DIAG_LOCK_BUSY=2, TASKQ_PAUSE_DIAG_DESTROYED=3,
 TASKQ_PAUSE_DIAG_PAUSED=4, TASKQ_PAUSE_DIAG_ACTIVE=5
};
struct taskq_pause_diagnostics { uint32_t reason; uint32_t active; };
struct IORecursiveLock { bool available=true; bool locked=false; };
static unsigned wakeups=0;
static bool IORecursiveLockTryLock(IORecursiveLock *lock) {
 if (!lock || !lock->available || lock->locked) return false;
 lock->locked=true; return true;
}
static void IORecursiveLockLock(IORecursiveLock *lock) {
 assert(lock && !lock->locked); lock->locked=true;
}
static void IORecursiveLockUnlock(IORecursiveLock *lock) {
 assert(lock && lock->locked); lock->locked=false;
}
static void IORecursiveLockWakeup(IORecursiveLock *,void *,bool) { ++wakeups; }
struct task { unsigned int t_flags=0; };
struct task_list {};
struct taskq { enum taskq_state tq_state=TQ_S_CREATED;
 IORecursiveLock *tq_mtx=nullptr; unsigned int tq_active=0; int tq_paused=0;
 struct task_list tq_worklist; };
#define TASK_ONQUEUE 1
#define ISSET(value,bit) ((value)&(bit))
#define SET(value,bit) ((value)|=(bit))
#define TAILQ_INSERT_TAIL(head,item,field) do { (void)(head); (void)(item); } while(0)
'''

MAIN = r'''
int main() {
 unsigned tests=0;
 taskq_pause_diagnostics d{};
 assert(taskq_try_pause_with_diagnostics(nullptr,&d)==ENXIO);
 assert(d.reason==TASKQ_PAUSE_DIAG_INVALID && d.active==0); ++tests;
 taskq missing{};
 assert(taskq_try_pause_with_diagnostics(&missing,&d)==ENXIO);
 assert(d.reason==TASKQ_PAUSE_DIAG_INVALID && d.active==0); ++tests;
 IORecursiveLock lock{};
 taskq q{}; q.tq_mtx=&lock; q.tq_active=7; lock.locked=true;
 assert(taskq_try_pause_with_diagnostics(&q,&d)==EBUSY);
 assert(d.reason==TASKQ_PAUSE_DIAG_LOCK_BUSY && d.active==UINT32_MAX);
 assert(q.tq_paused==0 && lock.locked); ++tests;
 lock.locked=false; q.tq_state=TQ_S_DESTROYED;
 assert(taskq_try_pause_with_diagnostics(&q,&d)==ENXIO);
 assert(d.reason==TASKQ_PAUSE_DIAG_DESTROYED && d.active==7);
 assert(!lock.locked && q.tq_paused==0); ++tests;
 q.tq_state=TQ_S_RUNNING; q.tq_paused=1;
 assert(taskq_try_pause_with_diagnostics(&q,&d)==EBUSY);
 assert(d.reason==TASKQ_PAUSE_DIAG_PAUSED && d.active==7);
 assert(!lock.locked && q.tq_paused==1); ++tests;
 q.tq_paused=0; q.tq_active=3;
 assert(taskq_try_pause_with_diagnostics(&q,&d)==EBUSY);
 assert(d.reason==TASKQ_PAUSE_DIAG_ACTIVE && d.active==3);
 assert(!lock.locked && q.tq_paused==0); ++tests;
 q.tq_active=0;
 assert(taskq_try_pause_with_diagnostics(&q,&d)==0);
 assert(d.reason==TASKQ_PAUSE_DIAG_NONE && d.active==0);
 assert(!lock.locked && q.tq_paused==1); ++tests;
 IORecursiveLock legacyLock{}; taskq legacy{}; legacy.tq_mtx=&legacyLock;
 assert(taskq_try_pause(&legacy)==0 && legacy.tq_paused==1);
 legacy.tq_paused=0; legacy.tq_active=1;
 assert(taskq_try_pause(&legacy)==EBUSY && legacy.tq_paused==0);
 ++tests;
 IORecursiveLock deadLock{}; taskq dead{}; task deadTask{};
 dead.tq_state=TQ_S_DESTROYED; dead.tq_mtx=&deadLock;
 assert(task_add(&dead,&deadTask)==0 && deadTask.t_flags==0);
 assert(!deadLock.locked && wakeups==0); ++tests;
 IORecursiveLock liveLock{}; taskq live{}; task liveTask{};
 live.tq_state=TQ_S_RUNNING; live.tq_mtx=&liveLock;
 assert(task_add(&live,&liveTask)==1 && ISSET(liveTask.t_flags,TASK_ONQUEUE));
 assert(!liveLock.locked && wakeups==1); ++tests;
 std::printf("{\"taskq_pause_and_add_scenarios\":%u}\n",tests);
}
'''

with tempfile.TemporaryDirectory(prefix="taskq-pause-diag-") as directory:
    cpp = Path(directory) / "test.cpp"
    exe = Path(directory) / "test"
    cpp.write_text(HARNESS + "\n" + "\n".join(methods) + MAIN)
    subprocess.run([
        "xcrun", "clang++", "-std=c++17", "-O1", "-g",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        str(cpp), "-o", str(exe),
    ], check=True)
    subprocess.run([str(exe)], check=True)
