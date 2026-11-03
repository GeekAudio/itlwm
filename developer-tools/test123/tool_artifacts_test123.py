"""Read-only, offline build-receipt checks for Tool123 / Kernel Test122."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import stat

COMPONENTS = {
    "sender": {
        "source": "developer-tools/test123/router-status/awdl_router_rx_lease_sender_test123.c",
        "protocol": "developer-tools/test123/router-status/dual_sender_protocol_test123.py",
        "target": "aarch64-linux-musl",
        "dependencies": (
            "developer-tools/test123/router-status/awdl_router_rx_lease_sender_test123.c",
            "developer-tools/test123/router-status/router_sender_schedule_test123.h",
            "developer-tools/test089/txstatus-observer/radiotap_parser.h",
            "developer-tools/test089/txstatus-observer/radiotap_parser.c",
        ),
    },
    "listener": {
        "source": "developer-tools/test123/awdl0_unicast_listener_test123.c",
        "protocol": "developer-tools/test123/listener_protocol_test123.py",
        "target": "x86_64-apple-macos",
        "dependencies": ("developer-tools/test123/awdl0_unicast_listener_test123.c",),
    },
}
CODEC = "developer-tools/test122/router-status/packetset_correlated_test122.py"


class ArtifactError(ValueError):
    pass


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read(path: Path, root: Path, uid: int, *, private: bool = False) -> bytes:
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise ArtifactError("artifact_path_not_absolute_regular")
    resolved = path.resolve(strict=True)
    if resolved != path or not resolved.is_relative_to(root):
        raise ArtifactError("artifact_path_outside_bound_root")
    meta = path.stat()
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != uid or
            meta.st_mode & 0o022):
        raise ArtifactError("artifact_owner_or_permissions_invalid")
    if private and (meta.st_mode & 0o077 or
                    path.parent.stat().st_uid != uid or
                    path.parent.stat().st_mode & 0o077):
        raise ArtifactError("receipt_not_private")
    return path.read_bytes()


def _object(raw: bytes) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ArtifactError("receipt_duplicate_key")
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except ArtifactError:
        raise
    except (ValueError, UnicodeError) as error:
        raise ArtifactError("receipt_invalid_json") from error
    if not isinstance(value, dict):
        raise ArtifactError("receipt_not_object")
    return value


def validate_build_receipt(path, *, kind: str, repo_root, private_root) -> dict:
    """Verify actual artifacts. Never executes a receipt command or binary."""
    if kind not in COMPONENTS:
        raise ArtifactError("artifact_kind_invalid")
    repo = Path(repo_root).resolve(strict=True)
    private = Path(private_root).resolve(strict=True)
    uid = repo.stat().st_uid
    raw = _read(Path(path), private, uid, private=True)
    value = _object(raw)
    expected = COMPONENTS[kind]
    if (value.get("schema") != f"test123-{kind}-build-private/v1" or
            value.get("tool_id") != "Tool123" or
            value.get("candidate") != "25G332-Test122" or
            value.get("running_kernel_test") != "Test122" or
            value.get("status") != "built_offline" or
            value.get("rf_tested") is not False or
            type(value.get("exit_code")) is not int or value["exit_code"] != 0 or
            value.get("target") != expected["target"]):
        raise ArtifactError("artifact_receipt_contract_mismatch")
    for field, relative in (("source", expected["source"]),
                             ("protocol_source", expected["protocol"])):
        actual_path = repo / relative
        if (value.get(field + "_path") != str(actual_path) or
                value.get(field + "_sha256") != _sha(_read(actual_path, repo, uid))):
            raise ArtifactError("artifact_source_mismatch:" + field)
    dependencies = value.get("compiled_dependency_sha256")
    if not isinstance(dependencies, dict) or set(dependencies) != set(expected["dependencies"]):
        raise ArtifactError("compiled_dependency_set_mismatch")
    for relative, digest in dependencies.items():
        if digest != _sha(_read(repo / relative, repo, uid)):
            raise ArtifactError("compiled_dependency_hash_mismatch:" + relative)
    if kind == "sender":
        if (value.get("codec_source_path") != str(repo / CODEC) or
                value.get("codec_source_sha256") != _sha(_read(repo / CODEC, repo, uid))):
            raise ArtifactError("artifact_codec_mismatch")
    binary_path = Path(str(value.get("binary_path", "")))
    binary = _read(binary_path, private, uid)
    if (binary_path.stat().st_mode & 0o111) == 0 or value.get("binary_sha256") != _sha(binary):
        raise ArtifactError("artifact_binary_mismatch")
    if kind == "sender":
        architecture_ok = (len(binary) >= 20 and binary[:6] == b"\x7fELF\x02\x01" and
                           int.from_bytes(binary[18:20], "little") == 183)
    else:
        architecture_ok = (len(binary) >= 8 and binary[:4] == b"\xcf\xfa\xed\xfe" and
                           int.from_bytes(binary[4:8], "little") == 0x01000007)
    if not architecture_ok:
        raise ArtifactError("artifact_binary_architecture_mismatch")
    command = value.get("command")
    if (not isinstance(command, list) or not command or
            any(not isinstance(arg, str) or not arg for arg in command) or
            value["source_path"] not in command or "-o" not in command or
            command.count("-o") != 1 or
            command.index("-o") + 1 >= len(command) or
            command[command.index("-o") + 1] != str(binary_path)):
        raise ArtifactError("artifact_build_command_mismatch")
    # This is a trusted local build record and drift check, not independent
    # proof that a compiler produced these bytes. Still reject structurally
    # false compiler/target claims instead of accepting any command with -o.
    common_flags = {"-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fstack-protector-strong"}
    if not common_flags.issubset(command):
        raise ArtifactError("artifact_build_flags_mismatch")
    if kind == "sender":
        compiler_ok = (Path(command[0]).name == "zig" and command[1:2] == ["cc"]
                       and command.count("-target") == 1
                       and command[command.index("-target") + 1:][:1] == [expected["target"]]
                       and "-static" in command and "-Os" in command
                       and "-D_FORTIFY_SOURCE=2" in command
                       and str(repo / "developer-tools/test089/txstatus-observer/radiotap_parser.c") in command)
    else:
        compiler_ok = (command[0] == "/usr/bin/clang" and command.count("-arch") == 1
                       and command[command.index("-arch") + 1:][:1] == ["x86_64"]
                       and "-O2" in command)
    if not compiler_ok:
        raise ArtifactError("artifact_build_compiler_or_target_mismatch")
    compiler = Path(command[0])
    if (not compiler.is_absolute() or not compiler.is_file() or
            value.get("compiler_sha256") != _sha(compiler.read_bytes())):
        raise ArtifactError("artifact_compiler_hash_mismatch")
    result = dict(value)
    result["validated_build_receipt_sha256"] = _sha(raw)
    return result
