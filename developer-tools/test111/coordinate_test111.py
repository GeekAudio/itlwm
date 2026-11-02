#!/usr/bin/env python3
"""Local, fail-closed coordinator for the Test111 channel-6 echo diagnostic.

Default mode validates a private config and local artifact hashes only.  A run
requires both --run and root, and every remote mutation gets a separate restore
SSH call in finally.  This tool never uploads files or stores SSH passwords.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import shlex
import stat
import subprocess
import sys
import time
from typing import Any


READY_MODULE_PATH = Path(__file__).resolve().parents[1] / "test110" / "openwrt_echo_ready.py"
_ready_spec = importlib.util.spec_from_file_location("test110_openwrt_echo_ready", READY_MODULE_PATH)
if _ready_spec is None or _ready_spec.loader is None:
    raise RuntimeError("cannot load the existing live READY validator")
_ready_module = importlib.util.module_from_spec(_ready_spec)
_ready_spec.loader.exec_module(_ready_module)
capture_ready = _ready_module.capture_ready
normalize_identity = _ready_module.normalize
READY_FIXED = _ready_module.FIXED

BUILD_ID = "25G332-Test111"
TEST112_BUILD_ID = "25G332-Test112"
COORDINATOR_SCHEMAS = {
    BUILD_ID: "test111-local-coordinator/v1",
    TEST112_BUILD_ID: "test112-local-coordinator/v1",
}
BUNDLE_ID = "org.geekaudio.AirportItlwm"
REMOTE_SCRIPT_NAME = "monitor_window111.sh"
REMOTE_PEER_NAME = "openwrt_echo110"
UUID_RE = re.compile(r"^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")


class CoordinatorError(RuntimeError):
    pass


def _coordinator_schema(build_id: str) -> str:
    try:
        return COORDINATOR_SCHEMAS[build_id]
    except (KeyError, TypeError) as error:
        raise CoordinatorError("unsupported coordinator build") from error


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def read_private_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.is_absolute() or config_path.is_symlink():
        raise CoordinatorError("config must be an absolute non-symlink path")
    info = config_path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size <= 0 or info.st_size > 32768:
        raise CoordinatorError("config must be a small private regular JSON file")
    try:
        authorized_uid = pwd.getpwnam("geek").pw_uid
    except KeyError as error:
        raise CoordinatorError("local geek account is missing") from error
    trusted_owners = {0, authorized_uid}
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid is not None:
        try:
            parsed_sudo_uid = int(sudo_uid, 10)
        except ValueError as error:
            raise CoordinatorError("invalid SUDO_UID") from error
        if parsed_sudo_uid != authorized_uid:
            raise CoordinatorError("SUDO_UID is not the authorized geek account")
        trusted_owners.add(parsed_sudo_uid)
    if info.st_uid not in trusted_owners:
        raise CoordinatorError("config owner is not trusted")
    try:
        value = json.loads(config_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise CoordinatorError("cannot read private config JSON") from error
    if not isinstance(value, dict):
        raise CoordinatorError("config root must be an object")
    return value


def _resolve_local_path(value: Any, name: str) -> Path:
    if not isinstance(value, str) or not value or "\n" in value or "\0" in value:
        raise CoordinatorError(f"invalid {name} path")
    path = Path(value)
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[2] / path
    return path


def _sha256_file(path: Path) -> str:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise CoordinatorError(f"not a regular file: {path.name}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        raise CoordinatorError(f"cannot hash local artifact: {path.name}") from error


def _validate_hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        raise CoordinatorError(f"invalid {name}")
    return value


def validate_config(config: dict[str, Any], *, build_id: str = BUILD_ID) -> tuple[dict[str, Any], dict[str, str]]:
    _coordinator_schema(build_id)
    required = {
        "ssh_target", "ssh_socket", "remote_dir", "output_dir",
        "expected_boot", "expected_uuid", "expected_build", "expected_reset_count",
        "helper_path", "helper_sha256", "helper_source_path", "helper_source_sha256",
        "remote_script_path", "remote_script_sha256", "peer_binary_path", "peer_sha256",
        "identity",
    }
    missing = sorted(required - set(config))
    if missing:
        raise CoordinatorError("config missing required fields: " + ", ".join(missing))
    if config["ssh_target"] != "root@192.168.5.1":
        raise CoordinatorError("ssh_target must be the configured OpenWrt root target")
    if not isinstance(config["ssh_socket"], str) or not Path(config["ssh_socket"]).is_absolute():
        raise CoordinatorError("ssh_socket must be an absolute path")
    if "\n" in config["ssh_socket"] or "\0" in config["ssh_socket"]:
        raise CoordinatorError("invalid ssh_socket")
    if type(config["expected_boot"]) is not int or config["expected_boot"] <= 0:
        raise CoordinatorError("expected_boot must be a positive integer")
    if type(config["expected_reset_count"]) is not int or config["expected_reset_count"] < 0:
        raise CoordinatorError("expected_reset_count must be a nonnegative integer")
    if config["expected_build"] != build_id:
        raise CoordinatorError("expected_build must be " + build_id)
    if not isinstance(config["expected_uuid"], str) or not UUID_RE.fullmatch(config["expected_uuid"]):
        raise CoordinatorError("expected_uuid must be uppercase canonical UUID")

    identity_raw = config["identity"]
    if not isinstance(identity_raw, dict):
        raise CoordinatorError("identity must be an object")
    try:
        identity = normalize_identity(identity_raw)
    except (KeyError, TypeError, ValueError) as error:
        raise CoordinatorError("invalid peer identity fields") from error
    token = identity["run_token"]
    remote_dir = config["remote_dir"]
    if remote_dir != f"/tmp/iw111echo-{token}":
        raise CoordinatorError("remote_dir must be unique and bound to identity.run_token")

    output_dir = Path(config["output_dir"])
    helper_path = _resolve_local_path(config["helper_path"], "helper")
    if not output_dir.is_absolute() or output_dir.name != f"run-{token}":
        raise CoordinatorError("output_dir must be a new run-token directory")
    if output_dir.parent.resolve() != helper_path.parent.resolve():
        raise CoordinatorError("output_dir must be a child of the private helper runtime directory")

    paths = {
        "helper": (helper_path, _validate_hash(config["helper_sha256"], "helper_sha256")),
        "helper_source": (_resolve_local_path(config["helper_source_path"], "helper source"),
                          _validate_hash(config["helper_source_sha256"], "helper_source_sha256")),
        "remote_script_source": (_resolve_local_path(config["remote_script_path"], "remote script source"),
                                 _validate_hash(config["remote_script_sha256"], "remote_script_sha256")),
        "peer_binary": (_resolve_local_path(config["peer_binary_path"], "peer binary"),
                        _validate_hash(config["peer_sha256"], "peer_sha256")),
    }
    normalized = dict(config)
    normalized["identity"] = identity
    normalized["helper_path_resolved"] = str(helper_path)
    normalized["output_dir_resolved"] = str(output_dir)
    normalized["remote_script_path_resolved"] = str(paths["remote_script_source"][0])
    normalized["peer_binary_path_resolved"] = str(paths["peer_binary"][0])
    normalized["helper_source_path_resolved"] = str(paths["helper_source"][0])
    normalized["remote_script_remote_path"] = remote_dir + "/" + REMOTE_SCRIPT_NAME
    normalized["peer_binary_remote_path"] = remote_dir + "/" + REMOTE_PEER_NAME

    verified: dict[str, str] = {}
    for name, (path, expected_hash) in paths.items():
        actual = _sha256_file(path)
        if actual != expected_hash:
            raise CoordinatorError(f"{name} SHA256 mismatch")
        verified[name] = actual
    return normalized, verified


def make_plan(config: dict[str, Any], *, build_id: str = BUILD_ID) -> dict[str, Any]:
    normalized, hashes = validate_config(config, build_id=build_id)
    return {
        "schema": _coordinator_schema(build_id),
        "mode": "plan",
        "hardware_action": False,
        "ssh_attempted": False,
        "local_runtime_read": False,
        "remote_restore_required_after_prepare": True,
        "build": normalized["expected_build"],
        "expected_boot_checked": False,
        "expected_uuid_checked": False,
        "hashes_verified": sorted(hashes),
        "helper_sha256": hashes["helper"],
        "automatic_retry": False,
        "airdrop_proven": False,
    }


def _run_local(command: list[str], timeout: float = 10.0, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("check", False)
    kwargs["timeout"] = timeout
    return subprocess.run(command, **kwargs)


def collect_runtime_snapshot(run_command=_run_local) -> dict[str, bytes]:
    commands = {
        "boot": ["/usr/sbin/sysctl", "-n", "kern.boottime"],
        "loaded": ["/usr/bin/kmutil", "showloaded", "--list-only", "--bundle-identifier", BUNDLE_ID],
        "ioreg": ["/usr/sbin/ioreg", "-r", "-n", "AirportItlwm", "-l", "-d", "1", "-a"],
        "en1": ["/sbin/ifconfig", "en1"],
        "awdl0": ["/sbin/ifconfig", "awdl0"],
    }
    raw: dict[str, bytes] = {}
    errors: list[str] = []
    for name, command in commands.items():
        try:
            result = run_command(command, timeout=10)
        except Exception as error:
            errors.append(name + ":command-error")
            continue
        stdout = result.stdout if isinstance(result.stdout, bytes) else str(result.stdout).encode()
        stderr = result.stderr if isinstance(result.stderr, bytes) else str(result.stderr).encode()
        raw[name] = stdout
        raw[name + "_stderr"] = stderr
        raw[name + "_exit"] = str(result.returncode).encode("ascii")
        if result.returncode != 0:
            errors.append(name + ":exit-nonzero")
    if errors:
        raw["snapshot_error"] = ",".join(errors).encode("ascii")
    return raw


def _parse_boot(raw: bytes) -> int:
    text = raw.decode("utf-8", "replace")
    match = re.search(r"\bsec\s*=\s*(\d+)", text)
    if match:
        return int(match.group(1))
    if re.fullmatch(r"\s*\d+\s*", text):
        return int(text.strip())
    raise CoordinatorError("cannot parse kern.boottime")


def _find_ioreg_records(value: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if "NativeTestBuild" in value:
            records.append(value)
        for child in value.values():
            records.extend(_find_ioreg_records(child))
    elif isinstance(value, (list, tuple)):
        for child in value:
            records.extend(_find_ioreg_records(child))
    return records


def _loaded_uuid(raw: bytes, expected_uuid: str) -> bool:
    text = raw.decode("utf-8", "replace")
    rows = [line for line in text.splitlines() if BUNDLE_ID + " " in line]
    expression = re.compile(re.escape(BUNDLE_ID) + r" \([^)]*\) " + re.escape(expected_uuid) + r"(?:\s|$)")
    return len(rows) == 1 and expression.search(rows[0]) is not None


def _ifconfig_state(raw: bytes) -> dict[str, Any]:
    text = raw.decode("utf-8", "replace")
    first = text.splitlines()[0] if text.splitlines() else ""
    flags = re.search(r"flags=[^<]*<([^>]*)>", first)
    up = bool(flags and "UP" in flags.group(1).split(","))
    ipv4: list[str] = []
    mac = None
    ipv6: list[str] = []
    for line in text.splitlines():
        match4 = re.match(r"\s*inet\s+(\d+(?:\.\d+){3})(?:\s|$)", line)
        if match4:
            try:
                ipv4.append(str(ipaddress.IPv4Address(match4.group(1))))
            except ipaddress.AddressValueError:
                pass
        matchmac = re.match(r"\s*ether\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\b", line)
        if matchmac:
            mac = matchmac.group(1).replace(":", "").lower()
        match6 = re.match(r"\s*inet6\s+([^\s]+)", line)
        if match6:
            candidate = match6.group(1).split("%", 1)[0]
            try:
                address = ipaddress.IPv6Address(candidate)
                if address.is_link_local:
                    ipv6.append(address.compressed.lower())
            except ipaddress.AddressValueError:
                pass
    return {"up": up, "ipv4": ipv4, "mac": mac, "link_local_ipv6": ipv6}


def inspect_snapshot(raw: dict[str, bytes], config: dict[str, Any]) -> dict[str, Any]:
    if raw.get("snapshot_error"):
        raise CoordinatorError("runtime snapshot commands failed")
    for name in ("boot", "loaded", "ioreg", "en1", "awdl0"):
        if name not in raw or int(raw.get(name + "_exit", b"1")) != 0:
            raise CoordinatorError("runtime snapshot incomplete: " + name)
    try:
        property_list = plistlib.loads(raw["ioreg"])
    except Exception as error:
        raise CoordinatorError("cannot parse IORegistry property-list snapshot") from error
    records = _find_ioreg_records(property_list)
    if len(records) != 1:
        raise CoordinatorError("expected exactly one AirportItlwm IORegistry build record")
    controller = records[0]
    identity = config["identity"]
    en1 = _ifconfig_state(raw["en1"])
    awdl = _ifconfig_state(raw["awdl0"])
    doorbell = controller.get("NativeP2PDirectedDataDoorbellIssued", 0)
    return {
        "boot": _parse_boot(raw["boot"]),
        "loaded_uuid_matches": _loaded_uuid(raw["loaded"], config["expected_uuid"]),
        "ioreg_record_count": len(records),
        "build": controller.get("NativeTestBuild"),
        "power_ready": type(controller.get("NativePowerReady")) is int and controller.get("NativePowerReady") == 1,
        "manual_trigger": type(controller.get("NativeP2PManualTrigger")) is bool and controller.get("NativeP2PManualTrigger") is True,
        "data_enabled": type(controller.get("NativeP2PDirectedDataEnabled")) is bool and controller.get("NativeP2PDirectedDataEnabled") is True,
        "data_compiled": type(controller.get("NativeP2PDirectedDataCompiled")) is bool and controller.get("NativeP2PDirectedDataCompiled") is True,
        "probe_attempted": controller.get("NativeP2PProbeAttempted"),
        "doorbell_issued": doorbell,
        "reset_count": controller.get("NativePowerResetCount"),
        "en1_up": en1["up"],
        "en1_ipv4_present": bool(en1["ipv4"]),
        "awdl0_up": awdl["up"],
        "awdl0_mac_matches": awdl["mac"] == identity["local_mac"],
        "awdl0_ipv6_matches": identity["local_ipv6"] in awdl["link_local_ipv6"],
    }


def validate_preflight(summary: dict[str, Any], config: dict[str, Any]) -> None:
    gates = {
        "boot": summary["boot"] == config["expected_boot"],
        "loaded_uuid_matches": summary["loaded_uuid_matches"],
        "ioreg_record_count": summary["ioreg_record_count"] == 1,
        "build": summary["build"] == config["expected_build"],
        "power_ready": summary["power_ready"],
        "manual_trigger": summary["manual_trigger"],
        "data_enabled": summary["data_enabled"],
        "data_compiled": summary["data_compiled"],
        "probe_attempted": type(summary["probe_attempted"]) is int and summary["probe_attempted"] == 0,
        "doorbell_issued": type(summary["doorbell_issued"]) is int and summary["doorbell_issued"] == 0,
        "reset_count": type(summary["reset_count"]) is int and summary["reset_count"] == config["expected_reset_count"],
        "en1_up": summary["en1_up"],
        "en1_ipv4_present": summary["en1_ipv4_present"],
        "awdl0_up": summary["awdl0_up"],
        "awdl0_mac_matches": summary["awdl0_mac_matches"],
        "awdl0_ipv6_matches": summary["awdl0_ipv6_matches"],
    }
    failed = [key for key, okay in gates.items() if not okay]
    if failed:
        raise CoordinatorError("preflight gate failed: " + failed[0])


def validate_postflight(before: dict[str, Any], after: dict[str, Any], config: dict[str, Any]) -> None:
    gates = {
        "boot": after["boot"] == config["expected_boot"] == before["boot"],
        "loaded_uuid_matches": after["loaded_uuid_matches"],
        "build": after["build"] == config["expected_build"],
        "power_ready": after["power_ready"],
        "reset_unchanged": type(before["reset_count"]) is int and after["reset_count"] == before["reset_count"],
        "en1_up": after["en1_up"],
        "en1_ipv4_present": after["en1_ipv4_present"],
        "awdl0_up": after["awdl0_up"],
        "awdl0_mac_matches": after["awdl0_mac_matches"],
        "awdl0_ipv6_matches": after["awdl0_ipv6_matches"],
    }
    failed = [key for key, okay in gates.items() if not okay]
    if failed:
        raise CoordinatorError("postflight gate failed: " + failed[0])


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    data = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    _write_private(path, data)


def _save_snapshot(directory: Path, prefix: str, raw: dict[str, bytes], summary: dict[str, Any] | None) -> None:
    for name, data in raw.items():
        suffix = ".plist" if name == "ioreg" else ".txt"
        _write_private(directory / f"{prefix}-{name}{suffix}", data)
    if summary is not None:
        _write_private_json(directory / f"{prefix}-summary.json", summary)


def verify_ssh_socket(path: str) -> None:
    try:
        info = os.stat(path)
    except OSError as error:
        raise CoordinatorError("SSH multiplex socket is not available") from error
    try:
        geek = pwd.getpwnam("geek")
    except KeyError as error:
        raise CoordinatorError("local geek account is missing") from error
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != geek.pw_uid:
        raise CoordinatorError("SSH multiplex socket must be a socket owned by geek")


def _remote_argv(config: dict[str, Any], remote_args: list[str]) -> list[str]:
    remote_command = shlex.join(remote_args)
    return ["/usr/bin/sudo", "-u", "geek", "/usr/bin/ssh", "-S", config["ssh_socket"],
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", config["ssh_target"], remote_command]


def _invoke_remote(config: dict[str, Any], remote_args: list[str], deps: Any,
                   timeout: float = 12.0) -> subprocess.CompletedProcess[bytes]:
    return deps.run(_remote_argv(config, remote_args), capture_output=True, timeout=timeout, check=False)


def _save_completed(directory: Path, stem: str, result: subprocess.CompletedProcess[bytes]) -> None:
    _write_private(directory / f"{stem}.stdout.raw", result.stdout or b"")
    _write_private(directory / f"{stem}.stderr.raw", result.stderr or b"")
    _write_private_json(directory / f"{stem}.result.json", {"returncode": result.returncode})


def _verify_remote_hash_output(output: bytes, config: dict[str, Any]) -> bool:
    expected = {
        config["remote_script_remote_path"]: config["remote_script_sha256"],
        config["peer_binary_remote_path"]: config["peer_sha256"],
    }
    found: dict[str, str] = {}
    for line in output.decode("utf-8", "replace").splitlines():
        match = re.match(r"^([0-9a-f]{64})\s+\*?(.+)$", line)
        if match:
            found[match.group(2).strip()] = match.group(1)
    return found == expected


def _colon_mac(compact: str) -> str:
    if not isinstance(compact, str) or not re.fullmatch(r"[0-9a-f]{12}", compact):
        raise CoordinatorError("MAC must be normalized lowercase hex")
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def _peer_remote_args(config: dict[str, Any]) -> list[str]:
    identity = config["identity"]
    return [config["remote_script_remote_path"], "--run", "--state-dir", config["remote_dir"],
            "--echo-binary", config["peer_binary_remote_path"],
            "--local-mac", _colon_mac(identity["local_mac"]),
            "--peer-mac", _colon_mac(identity["peer_mac"]),
            "--local-ipv6", identity["local_ipv6"],
            "--peer-ipv6", identity["peer_ipv6"],
            "--nonce", identity["nonce"],
            "--run-token", identity["run_token"]]


class LivePeerView:
    def __init__(self, ssh_process: Any, tee_process: Any):
        self._ssh_process = ssh_process
        self._tee_process = tee_process
        self.stdout = tee_process.stdout

    def poll(self):
        return self._ssh_process.poll()


class PeerSession:
    def __init__(self, ssh_process: Any, tee_process: Any, directory: Path):
        self.ssh_process = ssh_process
        self.tee_process = tee_process
        self.directory = directory
        self.ready_process = LivePeerView(ssh_process, tee_process)
        self.finished = False
        self.returncode: int | None = None

    def collect(self, timeout: float = 25.0) -> int:
        if self.finished:
            return int(self.returncode or 0)
        tail, _ = self.tee_process.communicate(timeout=timeout)
        _write_private(self.directory / "peer.stdout.remaining.raw", tail or b"")
        self.returncode = self.ssh_process.wait(timeout=timeout)
        self.finished = True
        _write_private_json(self.directory / "peer.result.json", {"returncode": self.returncode})
        return self.returncode

    def stop_local(self) -> None:
        for process in (self.ssh_process, self.tee_process):
            try:
                if process.poll() is None:
                    process.terminate()
            except Exception:
                pass
        for process in (self.tee_process, self.ssh_process):
            try:
                process.wait(timeout=1)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass


def start_peer_session(config: dict[str, Any], directory: Path, deps: Any) -> PeerSession:
    ssh_args = _remote_argv(config, _peer_remote_args(config))
    stderr_path = directory / "peer.stderr.raw"
    tee_stderr_path = directory / "peer.tee.stderr.raw"
    raw_stdout_path = directory / "peer.stdout.raw"
    if raw_stdout_path.exists() or raw_stdout_path.is_symlink():
        raise CoordinatorError("peer stdout path already exists")
    ssh_process = None
    tee_process = None
    try:
        with stderr_path.open("xb") as ssh_stderr, tee_stderr_path.open("xb") as tee_stderr:
            ssh_process = deps.popen(ssh_args, stdout=subprocess.PIPE, stderr=ssh_stderr, bufsize=0)
            if ssh_process.stdout is None:
                raise CoordinatorError("SSH peer stdout pipe missing")
            tee_process = deps.popen(["/usr/bin/tee", str(raw_stdout_path)],
                                     stdin=ssh_process.stdout, stdout=subprocess.PIPE,
                                     stderr=tee_stderr, bufsize=0)
            ssh_process.stdout.close()
    except BaseException:
        for process in (tee_process, ssh_process):
            if process is None:
                continue
            try:
                if process is ssh_process and ssh_process.stdout is not None:
                    ssh_process.stdout.close()
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=1)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        raise
    return PeerSession(ssh_process, tee_process, directory)


def _helper_argv(config: dict[str, Any], ready_path: Path) -> list[str]:
    identity = config["identity"]
    mac = identity["peer_mac"]
    peer_mac = ":".join(mac[index:index + 2] for index in range(0, 12, 2))
    return [config["helper_path_resolved"],
            "--expect-build", config["expected_build"],
            "--expect-uuid", config["expected_uuid"],
            "--peer-mac", peer_mac,
            "--local-ipv6", identity["local_ipv6"],
            "--nonce", identity["nonce"],
            "--run-token", identity["run_token"],
            "--peer-ipv6", identity["peer_ipv6"],
            "--peer-ready-file", str(ready_path),
            "--run"]


def _parse_json_lines(raw: bytes) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for line in raw.splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                values.append(value)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    return values


def _parse_json_line(raw: bytes) -> dict[str, Any] | None:
    values = _parse_json_lines(raw)
    return values[-1] if values else None


def _parse_peer_result(raw: bytes) -> dict[str, Any] | None:
    values = [value for value in _parse_json_lines(raw) if value.get("event") == "RESULT"]
    return values[-1] if values else None


def _geek_ids() -> tuple[int, int]:
    account = pwd.getpwnam("geek")
    return account.pw_uid, account.pw_gid


def _ensure_new_private_directory(config: dict[str, Any]) -> Path:
    path = Path(config["output_dir_resolved"])
    parent = path.parent
    parent_info = parent.stat()
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_mode & 0o077:
        raise CoordinatorError("helper runtime parent must be private")
    if path.exists() or path.is_symlink():
        raise CoordinatorError("run-token output directory must be new")
    os.mkdir(path, 0o700)
    uid, gid = _geek_ids()
    os.chown(path, uid, gid)
    os.chmod(path, 0o700)
    return path


def _chown_new_files(directory: Path) -> None:
    uid, gid = _geek_ids()
    for path in directory.iterdir():
        if path.is_symlink():
            continue
        info = path.lstat()
        if stat.S_ISREG(info.st_mode):
            os.chmod(path, 0o600)
            os.chown(path, uid, gid)


class RealDeps:
    run = staticmethod(_run_local)
    popen = staticmethod(subprocess.Popen)
    snapshot = staticmethod(collect_runtime_snapshot)
    capture_ready = staticmethod(capture_ready)

    @staticmethod
    def start_peer(config: dict[str, Any], directory: Path) -> PeerSession:
        return start_peer_session(config, directory, RealDeps)

    monotonic = staticmethod(time.monotonic)
    geteuid = staticmethod(os.geteuid)
    verify_socket = staticmethod(verify_ssh_socket)


def execute_run(config: dict[str, Any], deps: Any = RealDeps, *,
                build_id: str = BUILD_ID) -> dict[str, Any]:
    os.umask(0o077)
    normalized, hashes = validate_config(config, build_id=build_id)
    if deps.geteuid() != 0:
        raise CoordinatorError("--run requires effective uid 0")
    directory = _ensure_new_private_directory(normalized)
    identity = normalized["identity"]
    ready_path = directory / f"peer-ready-{identity['run_token']}.json"
    result: dict[str, Any] = {
        "schema": _coordinator_schema(build_id),
        "mode": "run",
        "build": build_id,
        "hardware_action": False,
        "router_mutation_attempted": False,
        "rf_window_attempted": False,
        "ssh_attempted": False,
        "arm_attempted": False,
        "airdrop_proven": False,
        "helper_sha256": hashes["helper"],
        "run_directory": str(directory),
    }
    before_raw: dict[str, bytes] | None = None
    before_summary: dict[str, Any] | None = None
    remote_touched = False
    peer: PeerSession | None = None
    helper_cp: subprocess.CompletedProcess[bytes] | None = None
    failure: str | None = None
    restore_rc: int | None = None
    postflight_ok: bool | None = None

    try:
        deps.verify_socket(normalized["ssh_socket"])
        before_raw = deps.snapshot()
        try:
            before_summary = inspect_snapshot(before_raw, normalized)
        except Exception:
            _save_snapshot(directory, "before", before_raw, None)
            raise
        _save_snapshot(directory, "before", before_raw, before_summary)
        validate_preflight(before_summary, normalized)

        result["ssh_attempted"] = True
        remote_hash_args = ["sha256sum", normalized["remote_script_remote_path"],
                            normalized["peer_binary_remote_path"]]
        remote_hash = _invoke_remote(normalized, remote_hash_args, deps)
        _save_completed(directory, "remote-hash", remote_hash)
        if remote_hash.returncode != 0 or not _verify_remote_hash_output(remote_hash.stdout or b"", normalized):
            raise CoordinatorError("remote script/peer SHA256 verification failed")

        prepare_args = [normalized["remote_script_remote_path"], "--prepare",
                        "--state-dir", normalized["remote_dir"],
                        "--run-token", identity["run_token"],
                        "--lease-seconds", "60"]
        remote_touched = True
        result["router_mutation_attempted"] = True
        prepare = _invoke_remote(normalized, prepare_args, deps)
        _save_completed(directory, "remote-prepare", prepare)
        if prepare.returncode != 0:
            raise CoordinatorError("remote prepare failed; restore will run")
        result["hardware_action"] = True

        launched = deps.monotonic()
        result["rf_window_attempted"] = True
        peer = deps.start_peer(normalized, directory)
        receipt = deps.capture_ready(peer.ready_process, launched, identity, ready_path)
        if not ready_path.exists() or ready_path.is_symlink():
            raise CoordinatorError("live READY receipt was not created")
        ready_info = ready_path.stat()
        if not stat.S_ISREG(ready_info.st_mode) or ready_info.st_mode & 0o077:
            raise CoordinatorError("live READY receipt is not private")
        result["live_ready_captured"] = True
        result["live_ready_sha256"] = receipt.get("router_ready_sha256")
        result["arm_attempted"] = True

        helper_args = _helper_argv(normalized, ready_path)
        try:
            helper_cp = deps.run(helper_args, capture_output=True, timeout=12, check=False)
        except subprocess.TimeoutExpired as timeout_error:
            stdout = timeout_error.stdout or b""
            stderr = timeout_error.stderr or b""
            if isinstance(stdout, str):
                stdout = stdout.encode()
            if isinstance(stderr, str):
                stderr = stderr.encode()
            _write_private(directory / "helper.stdout.raw", stdout)
            _write_private(directory / "helper.stderr.raw", stderr)
            _write_private_json(directory / "helper.result.json", {"timed_out": True, "timeout_seconds": 12})
            raise CoordinatorError(build_id + " helper exceeded 12 seconds") from timeout_error
        _save_completed(directory, "helper", helper_cp)
        helper_summary = _parse_json_line(helper_cp.stdout or b"")
        result["helper_exit_code"] = helper_cp.returncode
        result["helper_summary"] = helper_summary

        peer_rc = peer.collect(timeout=25)
        result["peer_exit_code"] = peer_rc
        result["peer_result"] = _parse_peer_result((directory / "peer.stdout.raw").read_bytes())
        result["orchestration_completed"] = True
    except Exception as error:
        failure = error.__class__.__name__ + ": " + str(error)
        result["orchestration_completed"] = False
    finally:
        if remote_touched:
            restore_args = [normalized["remote_script_remote_path"], "--restore",
                            "--state-dir", normalized["remote_dir"],
                            "--run-token", identity["run_token"]]
            try:
                restore = _invoke_remote(normalized, restore_args, deps, timeout=45)
                _save_completed(directory, "remote-restore", restore)
                restore_rc = restore.returncode
                if restore_rc != 0:
                    failure = failure or "CoordinatorError: remote restore returned nonzero"
            except Exception as error:
                failure = failure or (error.__class__.__name__ + ": restore command failed")
                _write_private_json(directory / "remote-restore.result.json", {"failed": True})
        if peer is not None and not peer.finished:
            try:
                peer_rc = peer.collect(timeout=5)
                result["peer_exit_code"] = peer_rc
                result["peer_result"] = _parse_peer_result((directory / "peer.stdout.raw").read_bytes())
            except Exception:
                peer.stop_local()
                result["peer_exit_code"] = None
                result["peer_collection_timed_out"] = True
        if before_raw is not None:
            try:
                after_raw = deps.snapshot()
                after_summary = inspect_snapshot(after_raw, normalized)
                _save_snapshot(directory, "after", after_raw, after_summary)
                if before_summary is not None:
                    validate_postflight(before_summary, after_summary, normalized)
                    postflight_ok = True
                else:
                    postflight_ok = False
            except Exception as error:
                postflight_ok = False
                failure = failure or (error.__class__.__name__ + ": postflight failed")
        result["remote_restore_exit_code"] = restore_rc
        result["postflight_ok"] = postflight_ok
        result["orchestration_completed"] = bool(
            result.get("orchestration_completed") and not failure and
            (not remote_touched or restore_rc == 0) and postflight_ok is True)
        result["matched_peer_return_proven"] = bool(
            isinstance(result.get("helper_summary"), dict) and
            result["helper_summary"].get("matched_peer_return_proven") is True)
        result["ifnet_delivery_proven"] = bool(
            isinstance(result.get("helper_summary"), dict) and
            result["helper_summary"].get("ifnet_delivery_proven") is True)
        result["peer_receipt_proven"] = False
        result["radio_ack_proven"] = False
        result["airdrop_proven"] = False
        if failure:
            result["error"] = failure
        try:
            _write_private_json(directory / "coordinator-result.json", result)
        except Exception:
            pass
        try:
            _chown_new_files(directory)
        except Exception:
            pass
    return result


def main(argv: list[str] | None = None, *, build_id: str = BUILD_ID) -> int:
    schema = _coordinator_schema(build_id)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="absolute mode-0600 private JSON config")
    parser.add_argument("--run", action="store_true", help="execute after strict preflight; requires root")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        config = read_private_config(args.config)
        if not args.run:
            result = make_plan(config, build_id=build_id)
        else:
            result = execute_run(config, build_id=build_id)
        sys.stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n")
        return 0 if not args.run or result.get("orchestration_completed") else 1
    except Exception as error:
        sys.stdout.write(json.dumps({"schema": schema, "mode": "error",
                                     "hardware_action": False, "ssh_attempted": False,
                                     "airdrop_proven": False,
                                     "error": error.__class__.__name__ + ": " + str(error)},
                                    sort_keys=True, ensure_ascii=False) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
