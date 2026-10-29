#!/usr/bin/env python3
"""Opt-in root coordinator; authorize before starting the short capture window.

Default is an offline description. --run requires fresh phone/Finder preparation,
a fresh boot, and an already authenticated user-owned SSH control socket. It
never mounts/writes EFI, logs in, stores a password, or retries an observation.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import select
import secrets
import signal
import stat
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
DURATION=20
MAX_CAPTURE_PACKETS=4096
BUILD='25G332-Test078'
CLEANUP_GRACE_SECONDS=4.0
TOTAL_DEADLINE_SECONDS=35.0
CAPTURE_DEADLINE_SECONDS=DURATION+5.0
RECEIVER_OUTPUT_PARENT=ROOT/'research/test078-router-runtime-private'
MAX_PROTOCOL_BUFFER_BYTES=65536


def ready_event(line):
    match=re.fullmatch(r'READY ([a-f0-9]{32}) window_seconds=(\d+) link_type=(\d+)',line)
    if not match:
        raise ValueError('Invalid capture readiness event')
    token,seconds,link=match.groups()
    if int(seconds)!=DURATION or int(link)!=127:
        raise ValueError('Expected the prepared 20-second Radiotap capture')
    return token


class StartFence:
    def __init__(self):
        self.consumed=False

    def start(self,line,callback):
        token=ready_event(line)
        if self.consumed:
            raise ValueError('Duplicate readiness event; never retry')
        self.consumed=True
        return token,callback()


class ReceiverBudget:
    """Use only parent-clock event receipt times; never compare child clocks."""
    def __init__(self):
        self.token=None
        self.ready_at=None
        self.window_at=None
        self.remaining=None
        self.closed=False

    def ready(self,line,now):
        if self.token is not None:
            raise ValueError('Duplicate capture readiness')
        self.token=ready_event(line)
        self.ready_at=now

    def window(self,line,now):
        match=re.fullmatch(r'WINDOW ([a-f0-9]{32}) remaining_seconds=(\d+)',line)
        if not match or match.group(1)!=self.token:
            raise ValueError('Wrong capture window token')
        remaining=int(match.group(2))
        if remaining>DURATION or (self.remaining is not None and remaining>self.remaining):
            raise ValueError('Regressing capture countdown')
        self.remaining=remaining
        self.window_at=now

    def available(self,now):
        if (self.closed or self.window_at is None or self.ready_at is None
                or now-self.window_at>1.6):
            return 0.0
        # Reserve two seconds for heartbeat granularity/transport/scheduling.
        # This is a conservative IPC budget, never a hardware-clock mapping.
        return max(0.0,min(DURATION-(now-self.ready_at),
                           self.remaining-(now-self.window_at))-2.0)


def load_collector():
    sys.path.insert(0,str(ROOT))
    spec=importlib.util.spec_from_file_location('test078_collector',ROOT/'capture_test078_resident_data_once.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def receiver_capture_args(python_executable, host, control_path, folder):
    """Build the bounded Test078 receiver command without changing its owner."""
    folder=Path(folder)
    return [python_executable,str(ROOT/'tools/openwrt_capture_once.py'),
        '--host',host,'--control-path',control_path,
        '--ap','wlan0','--ap','wlan1','--interface','wlan0','--monitor','iwawdl0',
        '--expect-ap','wlan0:0:6:2437:20','--expect-ap','wlan1:1:36:5180:160',
        '--capture','--duration',str(DURATION),'--max-packets',str(MAX_CAPTURE_PACKETS),
        '--output',str(folder/'receiver-private.pcap')]


def save_private(path,value,uid,gid):
    path.write_text(json.dumps(value,indent=2)+'\n')
    path.chmod(0o600)
    os.chown(path,uid,gid)


def ensure_user_private_directory(path, account):
    """Create one exact directory for the workspace user; never adopt existing paths.

    The coordinator runs as root, while the receiver runs as the workspace
    account. Create through a pinned parent directory fd so a pre-existing
    symlink or foreign-owned directory fails closed. Ownership is changed only
    on the inode this call just created.
    """
    path=Path(path)
    if not path.name or path.name in ('.','..'):
        raise ValueError('Invalid private output directory name')
    parent_flags=os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0)
    parent_fd=os.open(path.parent,parent_flags)
    child_fd=None
    created=False
    try:
        parent_stat=os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid!=account.pw_uid:
            raise PermissionError('Private output parent is not a workspace-user directory')
        try:
            os.mkdir(path.name,0o700,dir_fd=parent_fd)
            created=True
        except FileExistsError:
            pass
        child_flags=os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0)
        child_fd=os.open(path.name,child_flags,dir_fd=parent_fd)
        child_stat=os.fstat(child_fd)
        if not stat.S_ISDIR(child_stat.st_mode):
            raise PermissionError('Private output path is not a directory')
        if created:
            os.fchown(child_fd,account.pw_uid,account.pw_gid)
            os.fchmod(child_fd,0o700)
            child_stat=os.fstat(child_fd)
        elif child_stat.st_uid!=account.pw_uid or child_stat.st_mode&0o077:
            raise PermissionError('Existing private output directory has foreign ownership or permissions')
        if child_stat.st_uid!=account.pw_uid or child_stat.st_mode&0o077:
            raise PermissionError('Private output directory did not retain owner-only permissions')
    except BaseException:
        if child_fd is not None:
            os.close(child_fd)
            child_fd=None
        if created:
            # Remove only the just-created empty directory. Do not chown or
            # recursively clean any existing path after an error.
            try:
                os.rmdir(path.name,dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        if child_fd is not None:
            os.close(child_fd)
        os.close(parent_fd)
    return created


def verify_receiver_directory_write_access(folder, account, runner=subprocess.run):
    """Prove the actual capture user can create a file before any RF claim."""
    folder=Path(folder)
    probe=folder/('.receiver-write-preflight-'+secrets.token_hex(12))
    source=('import os,sys; fd=os.open(sys.argv[1], os.O_WRONLY|os.O_CREAT|'
            'os.O_EXCL|getattr(os,"O_NOFOLLOW",0), 0o600); os.close(fd)')
    try:
        result=runner(['/usr/bin/sudo','-n','-u',account.pw_name,'--',sys.executable,
                       '-c',source,str(probe)],stdin=subprocess.DEVNULL,
                      stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=3.0)
        if result.returncode!=0:
            raise PermissionError('Capture user could not create a private receiver file')
        info=os.lstat(probe)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=account.pw_uid:
            raise PermissionError('Receiver write probe has unexpected type or owner')
    finally:
        try:
            os.unlink(probe)
        except FileNotFoundError:
            pass


def prepare_receiver_output_folder(folder, account, runner=subprocess.run):
    """Prepare a fresh, user-writable run folder before launching the collector."""
    folder=Path(folder)
    if folder.parent!=RECEIVER_OUTPUT_PARENT:
        raise ValueError('Observation folder must be a direct child of the Test078 private output root')
    ensure_user_private_directory(RECEIVER_OUTPUT_PARENT,account)
    created=ensure_user_private_directory(folder,account)
    if not created:
        raise FileExistsError('Observation output already exists; refusing to overwrite it')
    try:
        verify_receiver_directory_write_access(folder,account,runner=runner)
    except BaseException:
        # The folder is ours and should still be empty because this check runs
        # before the report, receiver, native collector, or boot claim exists.
        try:
            os.rmdir(folder)
        except OSError:
            pass
        raise
    return folder


def create_private_native_stderr(folder, account):
    """Create a new regular 0600 log using descriptor-only metadata changes.

    The path is under a user-owned capture directory, so never chmod/chown by
    pathname after opening it. Keep stderr out of the coordinator protocol.
    """
    folder=Path(folder)
    name='native-stderr-private.log'
    directory_flags=(os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|
                     getattr(os,'O_NOFOLLOW',0))
    directory_fd=os.open(folder,directory_flags)
    stderr_fd=None
    try:
        directory_stat=os.fstat(directory_fd)
        if (not stat.S_ISDIR(directory_stat.st_mode) or
                directory_stat.st_uid!=account.pw_uid or
                directory_stat.st_mode&0o077):
            raise PermissionError('Native stderr directory is not private to the capture user')
        flags=(os.O_WRONLY|os.O_CREAT|os.O_EXCL|
               getattr(os,'O_NOFOLLOW',0))
        stderr_fd=os.open(name,flags,0o600,dir_fd=directory_fd)
        initial=os.fstat(stderr_fd)
        if not stat.S_ISREG(initial.st_mode):
            raise PermissionError('Native stderr path is not a regular file')
        os.fchown(stderr_fd,account.pw_uid,account.pw_gid)
        os.fchmod(stderr_fd,0o600)
        final=os.fstat(stderr_fd)
        if (not stat.S_ISREG(final.st_mode) or
                final.st_uid!=account.pw_uid or final.st_gid!=account.pw_gid or
                stat.S_IMODE(final.st_mode)!=0o600):
            raise PermissionError('Native stderr file did not retain owner-only mode')
        named=os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
        if (not stat.S_ISREG(named.st_mode) or named.st_dev!=final.st_dev or
                named.st_ino!=final.st_ino):
            raise PermissionError('Native stderr directory entry changed after creation')
        stream=os.fdopen(stderr_fd,'wb',buffering=0)
        stderr_fd=None
        return folder/name,stream
    finally:
        if stderr_fd is not None:
            os.close(stderr_fd)
        os.close(directory_fd)


def stop_group(process, deadline, initial_signal=signal.SIGTERM):
    if process is None:
        return {'leader':'not_started','descendants':'not_started',
                'signal_attempted':False}
    leader_was_running=process.poll() is None
    signals=[]
    try:
        os.killpg(process.pid,initial_signal)
        signals.append(signal.Signals(initial_signal).name)
    except ProcessLookupError:
        return {'leader':'not_found','descendants':'unknown',
                'signal_attempted':True,'signals':signals}
    except OSError as error:
        signals.append('initial_signal_error_' + type(error).__name__)
    first_wait=min(0.75,max(0.0,deadline-time.monotonic()))
    try:
        if process.poll() is None and first_wait:
            process.wait(timeout=first_wait)
    except subprocess.TimeoutExpired:
        pass
    # The group leader may have exited while a child (for example ssh or
    # tcpdump) remains. Probe the process group and make one bounded KILL
    # attempt whenever that group still exists.
    group_exists=False
    try:
        os.killpg(process.pid,0)
        group_exists=True
    except ProcessLookupError:
        pass
    except OSError as error:
        if getattr(error,'errno',None) == 1:  # EPERM still means it exists.
            group_exists=True
        else:
            signals.append('group_probe_error_' + type(error).__name__)
    if group_exists and time.monotonic()<deadline:
        try:
            os.killpg(process.pid,signal.SIGKILL)
            signals.append('SIGKILL')
        except ProcessLookupError:
            pass
        except OSError as error:
            signals.append('SIGKILL_error_' + type(error).__name__)
        remaining=max(0.0,deadline-time.monotonic())
        try:
            if process.poll() is None and remaining:
                process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            pass
    return {'leader':'exited' if process.poll() is not None else 'unreaped',
            'descendants':('kill_attempted_unverified' if group_exists else
                           'group_absent_at_probe' if leader_was_running else
                           'unverified'),
            'signal_attempted':True,'signals':signals}


def cleanup_children(receiver,native,deadline=None):
    """Try both child branches inside one short shared cleanup deadline."""
    if deadline is None:
        deadline=time.monotonic()+CLEANUP_GRACE_SECONDS
    outcomes={}
    # Stop the native collector first so an armed browse never outlives a
    # failed receiver. Its own SIGTERM handler bounds the child DNS-SD wait.
    try:
        outcomes['native']=stop_group(native,
            min(deadline,time.monotonic()+1.5),signal.SIGTERM)
    except (OSError,subprocess.SubprocessError) as error:
        outcomes['native']={'leader':'unknown','descendants':'unknown',
                            'signal_attempted':True,
                            'error_type':type(error).__name__}
    try:
        outcomes['receiver']=stop_group(receiver,deadline,signal.SIGINT)
    except (OSError,subprocess.SubprocessError) as error:
        outcomes['receiver']={'leader':'unknown','descendants':'unknown',
                              'signal_attempted':True,
                              'error_type':type(error).__name__}
    return outcomes


def cancel_native_after_receiver_failure(native,report,reason):
    """Signal the collector after an armed receiver fails; never wait its browse."""
    if not report.get('arm_released') or report.get('browse_window_complete'):
        return False
    if report.get('native_cancel_sent'):
        return False
    report['native_cancel_reason']=reason
    report['native_cancel_sent']=True
    if native is not None and native.poll() is None:
        try:
            native.send_signal(signal.SIGTERM)
            report['native_cancel_signal_sent']=True
        except (OSError,subprocess.SubprocessError) as error:
            report['native_cancel_signal_error']=type(error).__name__
    return True


def receiver_result_healthy(result, expected_token):
    """Whether the router capture returned its complete, unchanged-state proof."""
    return (isinstance(result,dict) and
        result.get('schema_version') == 1 and
        result.get('cancelled') is False and
        result.get('monitor_removed') is True and
        result.get('state_unchanged') is True and
        result.get('ready_token') == expected_token and
        type(result.get('tcpdump_exit_code')) is int and
        result.get('tcpdump_exit_code') == 0)


def record_native_summary_line(report,line):
    """Keep progress JSON separate; only the explicit completion field is authoritative."""
    summary=json.loads(line)
    if not isinstance(summary,dict):
        raise ValueError('Malformed native summary')
    report['native_summary_lines_seen']=report.get('native_summary_lines_seen',0)+1
    if 'native_browse_window_complete' in summary:
        complete=summary['native_browse_window_complete']
        if not isinstance(complete,bool):
            raise ValueError('Invalid native browse completion field')
        report['native_summary']=summary
        report['browse_window_complete']=complete
        report['native_summary_completion_reported']=True
    else:
        report['native_progress_summary']=summary
        report.setdefault('native_summary_completion_reported',False)


def protocol_lines(stream_state,chunk):
    """Append one raw FD read and return every complete protocol line in it."""
    buffer=stream_state[1]+chunk
    if len(buffer)>MAX_PROTOCOL_BUFFER_BYTES:
        raise ValueError('Capture protocol line limit')
    lines=[]
    while b'\n' in buffer:
        raw,buffer=buffer.split(b'\n',1)
        lines.append(raw)
    stream_state[1]=buffer
    return lines


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true')
    parser.add_argument('--phone-ready',action='store_true')
    parser.add_argument('--native-browser-active',action='store_true')
    parser.add_argument('--host')
    parser.add_argument('--control-path')
    parser.add_argument('--observation-id')
    args=parser.parse_args()
    if not args.run:
        print(json.dumps({'mode':'offline_description','capture_started':False,
            'native_query_started':False,'admin_verification_must_precede_capture':True,
            'same_test078_fresh_boot_required':True,
            'browse_window_seconds':20,
            'receiver_packet_limit':MAX_CAPTURE_PACKETS,
            'packet_limit_is_full_window_guarantee':False,
            'capture_deadline_seconds':CAPTURE_DEADLINE_SECONDS,
            'total_deadline_seconds':TOTAL_DEADLINE_SECONDS,
            'cleanup_grace_seconds':CLEANUP_GRACE_SECONDS}))
        return 0
    if os.geteuid()!=0 or not args.phone_ready or not args.native_browser_active:
        raise SystemExit('Require root and freshly confirmed phone/Finder preparation')
    if not args.host or not args.control_path or not args.observation_id:
        raise SystemExit('Missing explicit observer connection or observation id')
    total_started=time.monotonic()
    total_deadline=total_started+TOTAL_DEADLINE_SECONDS
    cleanup_deadline=total_deadline
    capture_deadline=total_deadline-CLEANUP_GRACE_SECONDS
    collector=load_collector()
    metadata=json.loads((ROOT/'research/test078-next-boot-private.json').read_text())
    boot=int(re.search(r'sec = (\d+)',subprocess.check_output(['/usr/sbin/sysctl','-n','kern.boottime'],text=True)).group(1))
    metadata_problems=collector.test078_metadata_problems(
        metadata,BUILD,boot_epoch=boot,root=ROOT)
    if metadata_problems:
        raise SystemExit('Test078 metadata is not explicitly armed for this boot; no capture started; fields='+
                         ','.join(metadata_problems))
    if time.monotonic() >= capture_deadline:
        raise TimeoutError('Preflight exhausted the bounded runtime; no capture started')
    folder=collector.observation_folder(ROOT,args.observation_id,boot,metadata.get('runtime_boot_epoch'))
    account=pwd.getpwuid(ROOT.stat().st_uid)
    socket_info=os.lstat(args.control_path)
    if not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid!=account.pw_uid:
        raise SystemExit('Require the already authenticated workspace-user control socket')
    if (ROOT/'research/test078-runtime-private/native-data-observation-private.json').is_symlink():
        raise SystemExit('Unexpected frozen observation path')
    try:
        prepare_receiver_output_folder(folder,account)
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        raise SystemExit('Receiver output preflight failed; capture not started; boot claim not consumed; reason='+type(error).__name__)
    report_path=folder/'coordinator-private.json'
    capture_args=receiver_capture_args(
        sys.executable,args.host,args.control_path,folder)
    native_args=[sys.executable,str(ROOT/'capture_test078_resident_data_once.py'),
        '--expect-build',BUILD,'--arm','--phone-ready','--native-browser-active',
        '--router-observation-id',args.observation_id,'--receiver-gated']
    report={'schema':1,'build':BUILD,'boot_epoch':boot,
        'observation_id':args.observation_id,'capture_started':False,
        'native_collector_invocations':0,'retry_allowed':False,
        'receiver_packet_limit':MAX_CAPTURE_PACKETS,
        'packet_limit_is_full_window_guarantee':False,
        'packet_limit_scope':'The 4096-packet cap can still fill before the 20-second window ends.',
        'root_authorized_before_receiver':True,'efi_modified':False,
        'clock_mapping_proven':False,'peer_receipt_proven':False,
        'radio_window_coverage_proven':False,'receiver_windows':[],
        'browse_released':False,'arm_released':False,
        'arm_return_received_during_receiver_heartbeat':False,
        'browse_window_complete':None,
        'native_summary_lines_seen':0,
        'native_summary_completion_reported':False,
        'total_deadline_seconds':TOTAL_DEADLINE_SECONDS,
        'cleanup_grace_seconds':CLEANUP_GRACE_SECONDS,
        'total_started_monotonic_ns':time.monotonic_ns(),
        'capture_deadline_monotonic_ns':int(capture_deadline*1_000_000_000),
        'deadline_scope':'Coordinator runtime through both child cleanup attempts; final private report persistence is recorded separately.'}
    receiver=native=None
    native_error_stream=None
    fence=StartFence()
    budget=ReceiverBudget()
    streams={}
    ready_line=None
    try:
        save_private(report_path,report,account.pw_uid,account.pw_gid)
        # Slow archive/identity/runtime preflight happens before the capture.
        # The collector then claims this boot and waits before native browsing.
        # Keep failures private instead of losing an unexplained exit after
        # the progress record. This does not turn stderr into protocol input.
        native_error_path,native_error_stream=create_private_native_stderr(
            folder,account)
        report['native_stderr_saved_private']=True
        native=subprocess.Popen(native_args,stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=native_error_stream,
            start_new_session=True)
        report['native_collector_invocations']=1
        streams[native.stdout]=['native',b'']
        save_private(report_path,report,account.pw_uid,account.pw_gid)
        def send_gate(command):
            if native.poll() is not None:
                raise ValueError('Native collector already stopped')
            native.stdin.write((command+'\n').encode('ascii'))
            native.stdin.flush()
        while streams:
            now=time.monotonic()
            remaining=capture_deadline-now
            if remaining<=0:
                raise TimeoutError('Capture deadline; do not retry this boot')
            if (report['arm_released'] and receiver is not None and
                    receiver.poll() not in (None,0)):
                cancel_native_after_receiver_failure(
                    native,report,'receiver_process_failed_after_arm')
            readable,_,_=select.select(list(streams),[],[],min(0.2,remaining))
            for stream in readable:
                name,buffer=streams[stream]
                chunk=os.read(stream.fileno(),65536)
                if not chunk:
                    if buffer:
                        raise ValueError('Incomplete coordinator protocol line')
                    del streams[stream]
                    if name=='receiver':
                        budget.closed=True
                        if not report['arm_released'] and native.poll() is None:
                            send_gate('ABORT')
                        elif report['arm_released'] and not receiver_result_healthy(
                                report.get('receiver_result'),report.get('receiver_run_id')):
                            cancel_native_after_receiver_failure(
                                native,report,'receiver_stream_closed_without_healthy_result')
                    continue
                for raw in protocol_lines(streams[stream],chunk):
                    line=raw.decode('utf-8')
                    now=time.monotonic()
                    if name=='native':
                        if line=='NATIVE-PREFLIGHT-READY':
                            if receiver is not None:
                                raise ValueError('Duplicate native preflight readiness')
                            report['native_preflight_ready_received_monotonic_ns']=time.monotonic_ns()
                            receiver=subprocess.Popen(['/usr/bin/sudo','-n','-u',account.pw_name,'--']+capture_args,
                                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                start_new_session=True)
                            streams[receiver.stdout]=['receiver',b'']
                            report['capture_started']=True
                            # The receiver captures for 20 seconds. The
                            # absolute Test078 deadline also reserves the
                            # shared cleanup grace for both child groups.
                            capture_deadline=min(
                                now+CAPTURE_DEADLINE_SECONDS,
                                total_deadline-CLEANUP_GRACE_SECONDS)
                            report['capture_deadline_monotonic_ns']=int(
                                capture_deadline*1_000_000_000)
                        elif line=='NATIVE-BROWSER-READY':
                            available=budget.available(now)
                            deadline_budget=capture_deadline-time.monotonic()
                            if (report['arm_released'] or available<12 or
                                    deadline_budget < DURATION+1.0 or
                                    receiver is None or receiver.poll() is not None):
                                send_gate('ABORT')
                                raise ValueError('Insufficient active receiver budget; no arm permitted')
                            report['arm_release_available_parent_budget_seconds']=round(available,6)
                            report['arm_release_parent_monotonic_ns']=time.monotonic_ns()
                            report['arm_released']=True
                            save_private(report_path,report,account.pw_uid,account.pw_gid)
                            send_gate('ARM')
                        elif line=='NATIVE-ARM-RETURNED':
                            report['arm_return_received_parent_monotonic_ns']=time.monotonic_ns()
                            report['arm_return_received_during_receiver_heartbeat']=bool(
                                report['arm_released'] and budget.available(now)>0
                                and receiver is not None and receiver.poll() is None)
                        elif line.startswith('{'):
                            # Progress summaries do not carry the completion
                            # field. Do not turn a missing field into False.
                            # No independent clock mapping is claimed.
                            record_native_summary_line(report,line)
                            report['receiver_browse_overlap_seconds']=None
                            report['receiver_browse_overlap_proven']=False
                        else:
                            raise ValueError('Unexpected native phase event')
                    elif line.startswith('READY '):
                        if receiver.poll() is not None:
                            raise ValueError('Receiver already stopped')
                        budget.ready(line,now)
                        ready_line=line
                        report['receiver_run_id']=budget.token
                        report['receiver_ready_received_monotonic_ns']=time.monotonic_ns()
                    elif line.startswith('WINDOW '):
                        budget.window(line,now)
                        report['receiver_windows'].append({'received_parent_monotonic_ns':time.monotonic_ns(),
                            'remaining_seconds':budget.remaining})
                        if not report['browse_released']:
                            if ready_line is None or budget.available(now)<15:
                                raise ValueError('Insufficient receiver budget before browsing')
                            token,_=fence.start(ready_line,lambda:send_gate('BROWSE'))
                            report['browse_released']=True
                            report['browse_release_parent_monotonic_ns']=time.monotonic_ns()
                    elif line.startswith('{'):
                        receiver_result=json.loads(line)
                        if not isinstance(receiver_result,dict):
                            raise ValueError('Malformed receiver result')
                        report['receiver_result']=receiver_result
                        budget.closed=True
                        if (report['arm_released'] and not receiver_result_healthy(
                                receiver_result,report.get('receiver_run_id'))):
                            cancel_native_after_receiver_failure(
                                native,report,'receiver_result_failed_after_arm')
                    else:
                        raise ValueError('Unexpected capture protocol')
            save_private(report_path,report,account.pw_uid,account.pw_gid)
        if receiver is not None and receiver.poll() is None:
            receiver.wait(timeout=max(0.0,min(0.25,capture_deadline-time.monotonic())))
            report['receiver_exit']=receiver.returncode
        if native.poll() is None:
            native.wait(timeout=max(0.0,min(0.25,capture_deadline-time.monotonic())))
        report['native_collector_exit']=native.returncode
        result=report.get('receiver_result',{})
        report['complete']=bool(receiver is not None and receiver.returncode==0 and native.returncode==0
            and result.get('cancelled') is False and result.get('state_unchanged') is True
            and result.get('monitor_removed') is True
            and result.get('ready_token')==report.get('receiver_run_id')
            and report['browse_released'] and report['arm_released']
            and report.get('browse_window_complete') is True
            and report['arm_return_received_during_receiver_heartbeat'])
        save_private(report_path,report,account.pw_uid,account.pw_gid)
        print(json.dumps({'complete':report['complete'],'native_collector_invocations':report['native_collector_invocations'],
            'browse_window_complete':report.get('browse_window_complete',False),
            'receiver_browse_overlap_proven':False,
            'new_efi_deployed':False,'peer_receipt_proven':False}))
        return 0 if report['complete'] else 2
    except (ValueError,TimeoutError,OSError,subprocess.SubprocessError) as error:
        report['complete']=False
        report['outcome']='incomplete_no_retry'
        report['error_type']=type(error).__name__
        print(json.dumps({'complete':False,'outcome':'incomplete_no_retry',
            'native_collector_invocations':report['native_collector_invocations']}))
        return 2
    except BaseException:
        report['complete']=False
        report['outcome']='incomplete_no_retry'
        raise
    finally:
        if native_error_stream is not None:
            native_error_stream.close()
        cleanup_started=time.monotonic()
        cleanup_deadline=min(total_deadline,
            cleanup_started+CLEANUP_GRACE_SECONDS)
        report['cleanup_deadline_monotonic_ns']=int(
            cleanup_deadline*1_000_000_000)
        report['process_cleanup']=cleanup_children(
            receiver,native,deadline=cleanup_deadline)
        report['cleanup_elapsed_seconds']=round(time.monotonic()-cleanup_started,3)
        report['total_elapsed_seconds']=round(time.monotonic()-total_started,3)
        report['total_deadline_met_before_report_persistence']=(
            time.monotonic()<=total_deadline)
        report['process_group_descendant_cleanup_globally_proven']=False
        for process in (receiver,native):
            if process is not None:
                for pipe in (process.stdin,process.stdout,process.stderr):
                    if pipe is not None:
                        try:
                            pipe.close()
                        except OSError:
                            report['pipe_close_error']=True
        save_private(report_path,report,account.pw_uid,account.pw_gid)


if __name__=='__main__':
    raise SystemExit(main())
