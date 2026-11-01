"""Bounded diagnostic subprocess cleanup; import is inert."""
from __future__ import annotations
import errno, os, signal, subprocess, time

def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as error:
        return error.errno != errno.ESRCH

def _signal_process_group(process: subprocess.Popen, signum: int) -> bool:
    try:
        os.killpg(process.pid, signum)
        return True
    except ProcessLookupError:
        if process.poll() is None:
            try:
                process.send_signal(signum)
                return True
            except OSError:
                return False
        return False
    except OSError:
        try:
            process.send_signal(signum)
            return True
        except OSError:
            return False

def run_wrapper_process_group(command: list[str], *, timeout: float = 180.0,
                              term_grace_seconds: float = 5.0) -> dict:
    """Run the active wrapper in a new session and reap its whole process group on timeout.

    The coordinator starts compiler/helper subprocesses before and during its
    bounded capture. Keeping the wrapper in its own session lets timeout cleanup
    terminate a stuck preflight compiler as well as the coordinator itself.
    """
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return {
            "returncode": process.returncode,
            "stdout": stdout or "",
            "stderr": stderr or "",
            "timed_out": False,
            "timeout_cleanup": None,
        }
    except subprocess.TimeoutExpired:
        cleanup = {
            "timeout_seconds": timeout,
            "term_grace_seconds": term_grace_seconds,
            "process_group_id": process.pid,
            "sigterm_sent": False,
            "sigkill_sent": False,
            "group_alive_after_term": None,
            "group_alive_after_kill": None,
            "process_reaped": False,
            "stdio_drained": False,
        }
        cleanup["sigterm_sent"] = _signal_process_group(process, signal.SIGTERM)
        grace_deadline = time.monotonic() + max(0.0, term_grace_seconds)

        try:
            stdout, stderr = process.communicate(timeout=term_grace_seconds)
            cleanup["stdio_drained"] = True
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.output or "", error.stderr or ""

        # Do not infer group exit from pipe EOF: a descendant can close or
        # redirect stdio and keep running after its parent exits on SIGTERM.
        while time.monotonic() < grace_deadline and _process_group_exists(process.pid):
            time.sleep(min(0.02, max(0.0, grace_deadline - time.monotonic())))
        cleanup["group_alive_after_term"] = _process_group_exists(process.pid)
        if cleanup["group_alive_after_term"]:
            cleanup["sigkill_sent"] = _signal_process_group(process, signal.SIGKILL)
            kill_deadline = time.monotonic() + max(0.2, term_grace_seconds)
            while time.monotonic() < kill_deadline and _process_group_exists(process.pid):
                time.sleep(min(0.02, max(0.0, kill_deadline - time.monotonic())))

        # Reap the direct wrapper without waiting on inherited pipes. If it
        # ignores/does not process SIGKILL promptly, force it directly and keep
        # every wait bounded.
        if process.poll() is None:
            try:
                process.wait(timeout=max(1.0, term_grace_seconds))
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except OSError:
                    pass
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass

        # Drain remaining output with a finite wait. A descendant that escaped
        # the session must not hold this administrator process indefinitely.
        if not cleanup["stdio_drained"]:
            try:
                stdout, stderr = process.communicate(timeout=1.0)
                cleanup["stdio_drained"] = True
            except subprocess.TimeoutExpired as error:
                stdout = error.output or stdout
                stderr = error.stderr or stderr
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            pass

        cleanup["group_alive_after_kill"] = _process_group_exists(process.pid)

        cleanup["process_reaped"] = process.poll() is not None
        return {
            "returncode": process.returncode,
            "stdout": stdout or "",
            "stderr": stderr or "",
            "timed_out": True,
            "timeout_cleanup": cleanup,
        }
