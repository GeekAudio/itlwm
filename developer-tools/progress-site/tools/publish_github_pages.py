#!/usr/bin/env python3
"""Publish only the reviewed milestone website to GeekAudio/itlwm Pages.

The script refreshes the public-safe data projection, validates a strict file
allowlist, updates an isolated Pages branch through the existing Git credential
helper, enables Pages when needed, and verifies the public readback. Credentials
are read into process memory only and are never written to disk or printed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "progress-site" / "dist"
REFRESH = ROOT / "progress-site" / "tools" / "refresh_data.py"
RESEARCH = ROOT / "research"
STATE_PATH = RESEARCH / "github-pages-state-private.json"
REPOSITORY = "GeekAudio/itlwm"
BRANCH = "gh-pages"
FILES = (
    "index.html",
    "milestones.html",
    "data.js",
    "assets/site.css",
    "assets/site.js",
    "assets/test-records.js",
)
RESTRICTED_PATTERNS = (
    re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])"),
    re.compile(r"(?i)\b(?:ssid|bssid)\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(?:api[_ -]?)?token\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(?:ghp_|github_pat_|gho_)[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:^|\s)(?:/Users/|/Volumes/|/private/|[A-Za-z]:\\)"),
)
API_ROOT = "https://api.github.com"


class PublishError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(args: list[str], *, cwd: Path | None = None, input_text: str | None = None,
        env_overrides: dict[str, str] | None = None) -> str:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if env_overrides:
        env.update(env_overrides)
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    if result.returncode:
        detail = result.stderr.strip().splitlines()
        safe = detail[-1] if detail else "command failed"
        raise PublishError(f"Command failed ({args[0]}): {safe[:300]}")
    return result.stdout.strip()


def github_token() -> str:
    try:
        output = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=True,
        ).stdout
    except Exception as error:
        raise PublishError("GitHub credential helper is unavailable") from error
    credentials = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    token = credentials.get("password", "")
    if not token:
        raise PublishError("No GitHub credential is available from the system Git credential helper")
    return token


def api_request(token: str, method: str, path: str, payload: dict | None = None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        API_ROOT + path,
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "GeekAudio-milestone-pages-publisher",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return 404, None
        try:
            message = json.loads(error.read().decode("utf-8")).get("message", "")
        except Exception:
            message = ""
        raise PublishError(f"GitHub API {method} returned HTTP {error.code}: {message[:240]}") from error
    except Exception as error:
        raise PublishError(f"GitHub API {method} failed: {type(error).__name__}") from error


def public_get(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "GeekAudio-milestone-pages-readback", "Cache-Control": "no-cache"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise PublishError(f"Public readback returned HTTP {response.status}")
        return response.read()


def snapshot_site() -> tuple[dict[str, bytes], dict]:
    run([sys.executable, str(REFRESH)], cwd=ROOT,
        env_overrides={"INTELWIRELESS_PAGES_PUBLISHER_ACTIVE": "1"})
    payload: dict[str, bytes] = {}
    for relative in FILES:
        source = SITE / relative
        if source.is_symlink() or not source.is_file():
            raise PublishError(f"Allowlisted website file is missing or unsafe: {relative}")
        data = source.read_bytes()
        if len(data) > 1_000_000:
            raise PublishError(f"Website file is unexpectedly large: {relative}")
        text = data.decode("utf-8")
        for pattern in RESTRICTED_PATTERNS:
            if pattern.search(text):
                raise PublishError(f"Public safety filter rejected {relative}")
        payload[relative] = data

    js = payload["data.js"].decode("utf-8")
    prefix = "window.PROGRESS_DATA = "
    if not js.startswith(prefix) or not js.rstrip().endswith(";"):
        raise PublishError("Generated data.js is not the expected safe projection")
    data = json.loads(js[len(prefix):].rstrip().removesuffix(";"))
    candidate = data.get("runningCandidate")
    if not isinstance(candidate, str) or not re.fullmatch(r"25G332-Test\d{3}", candidate):
        raise PublishError("The current local milestone snapshot has no approved Test candidate")
    candidate_label = candidate.rsplit("-", 1)[-1]
    if candidate_label not in data.get("validationLabel", ""):
        raise PublishError("The published validation label does not match the running candidate")
    records_js = payload["assets/test-records.js"].decode("utf-8")
    records_prefix = "window.TEST_RECORDS = "
    try:
        if not records_js.startswith(records_prefix) or not records_js.rstrip().endswith(";"):
            raise ValueError("Unexpected records format")
        records = json.loads(records_js[len(records_prefix):].rstrip().removesuffix(";"))
        if not isinstance(records, list) or len(records) != 1 or records[0].get("version") != candidate:
            raise ValueError("Records must contain only the running candidate")
    except (ValueError, AttributeError) as error:
        raise PublishError("Publish only the current version's verification record") from error
    if data.get("progressModel", {}).get("fixed_total") != 40:
        raise PublishError("The current validation denominator is not the fixed 40-item model")
    milestones = data.get("milestones", [])
    stages = {m.get("stage"): m for m in milestones if m.get("stage") in (5, 6, 7, 8)}
    if set(stages) != {5, 6, 7, 8} or any(
        not (milestone.get("current_summary") or milestone.get("evidence"))
        for milestone in stages.values()
    ):
        raise PublishError("Current evidence details are incomplete in stages 5 through 8")
    next_candidate = data.get("nextCandidate")
    next_label = next_candidate.rsplit("-", 1)[-1] if isinstance(next_candidate, str) else ""
    if next_label and re.fullmatch(r"Test\d{3}", next_label) and "test" + next_label[4:] in str(data.get("deploymentState", "")).lower():
        if any(next_label not in milestone.get("candidate_check", "") for milestone in stages.values()):
            raise PublishError("Candidate-specific next checks are incomplete in stages 5 through 8")
    return payload, data


def load_state() -> dict | None:
    try:
        value = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return value if value.get("repository") == REPOSITORY and value.get("branch") == BRANCH else None
    except (OSError, json.JSONDecodeError):
        return None


def choose_prefix(branch_files: set[str], branch_hashes: dict[str, str], state: dict | None,
                  source_path: str, current_hashes: dict[str, str]) -> str:
    site_root = source_path.strip("/")
    if state:
        previous = state.get("branch_prefix", "")
        old_hashes = state.get("files", {})
        intact = bool(old_hashes) and all(branch_hashes.get(f"{previous}/{name}".strip("/")) == digest
                                           for name, digest in old_hashes.items())
        if intact:
            return previous
    for candidate in (site_root, "/".join(filter(None, (site_root, "IntelWirelessNative")))):
        if all(branch_hashes.get(f"{candidate}/{name}".strip("/")) == digest
               for name, digest in current_hashes.items()):
            return candidate
    if branch_files:
        return "/".join(filter(None, (site_root, "IntelWirelessNative")))
    return site_root


def write_site_to_branch(payload: dict[str, bytes], prefix: str, branch_exists: bool) -> tuple[str, bool]:
    with tempfile.TemporaryDirectory(prefix="intelwireless-pages-") as tmp:
        checkout = Path(tmp) / "checkout"
        remote = f"https://github.com/{REPOSITORY}.git"
        if branch_exists:
            run(["git", "clone", "--quiet", "--single-branch", "--branch", BRANCH, remote, str(checkout)])
        else:
            checkout.mkdir()
            run(["git", "init", "--quiet", "--initial-branch", BRANCH], cwd=checkout)
            run(["git", "remote", "add", "origin", remote], cwd=checkout)

        for relative, data in payload.items():
            destination = checkout / prefix / relative if prefix else checkout / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)

        staged_paths = [f"{prefix}/{name}".strip("/") for name in FILES]
        run(["git", "add", "--", *staged_paths], cwd=checkout)
        staged = set(run(["git", "diff", "--cached", "--name-only"], cwd=checkout).splitlines())
        allowed = set(staged_paths)
        if not staged.issubset(allowed):
            raise PublishError("The Pages commit contains files outside the static-site allowlist")
        current = run(["git", "rev-parse", "HEAD"], cwd=checkout) if branch_exists else ""
        if not staged:
            return current, False
        run(["git", "-c", "user.name=GeekAudio", "-c", "user.email=19627926+GeekAudio@users.noreply.github.com",
             "commit", "--quiet", "-m", "Update Intel Wi-Fi milestone site"], cwd=checkout)
        commit = run(["git", "rev-parse", "HEAD"], cwd=checkout)
        run(["git", "push", "--quiet", "origin", f"HEAD:refs/heads/{BRANCH}"], cwd=checkout)
        return commit, True


def main() -> int:
    payload, data = snapshot_site()
    runtime_label = data["runningCandidate"].rsplit("-", 1)[-1]
    next_candidate = data.get("nextCandidate")
    next_label = next_candidate.rsplit("-", 1)[-1] if isinstance(next_candidate, str) else ""
    page_candidate = (next_label if re.fullmatch(r"Test\d{3}", next_label)
                      and next_label.lower() in str(data.get("deploymentState", "")).lower()
                      else runtime_label)
    hashes = {name: sha256(content) for name, content in payload.items()}
    token = github_token()
    pages_status, pages = api_request(token, "GET", f"/repos/{REPOSITORY}/pages")
    if pages_status == 200:
        source = pages.get("source") or {}
        if pages.get("build_type") == "workflow" or source.get("branch") != BRANCH:
            raise PublishError("Existing Pages site uses a different source; preserving it without changes")
        source_path = source.get("path", "/")
        if source_path not in ("/", "/docs"):
            raise PublishError("Existing Pages source path is not a supported static directory")
    elif pages_status == 404:
        source_path = "/"
    else:
        raise PublishError(f"Unexpected Pages API status: {pages_status}")

    ref_status, ref = api_request(token, "GET", f"/repos/{REPOSITORY}/git/ref/heads/{BRANCH}")
    branch_exists = ref_status == 200
    if not branch_exists and ref_status != 404:
        raise PublishError(f"Unexpected branch lookup status: {ref_status}")
    branch_files: set[str] = set()
    branch_hashes: dict[str, str] = {}
    if branch_exists:
        with tempfile.TemporaryDirectory(prefix="intelwireless-pages-tree-") as tmp:
            clone = Path(tmp) / "checkout"
            run(["git", "clone", "--quiet", "--single-branch", "--branch", BRANCH,
                 f"https://github.com/{REPOSITORY}.git", str(clone)])
            branch_files = set(run(["git", "ls-tree", "-r", "--name-only", "HEAD"], cwd=clone).splitlines())
            for name in branch_files:
                file_path = clone / name
                if file_path.is_file() and not file_path.is_symlink():
                    branch_hashes[name] = sha256(file_path.read_bytes())
    state = load_state()
    prefix = choose_prefix(branch_files, branch_hashes, state, source_path, hashes)
    commit, changed = write_site_to_branch(payload, prefix, branch_exists)

    if pages_status == 404:
        try:
            created_status, pages = api_request(
                token,
                "POST",
                f"/repos/{REPOSITORY}/pages",
                {"source": {"branch": BRANCH, "path": "/"}},
            )
            if created_status not in (201, 202):
                raise PublishError(f"GitHub Pages setup returned HTTP {created_status}")
        except PublishError as error:
            if "returned HTTP 409" not in str(error):
                raise
            pages_status, pages = api_request(token, "GET", f"/repos/{REPOSITORY}/pages")
            source = (pages or {}).get("source") or {}
            if pages_status != 200 or source.get("branch") != BRANCH or source.get("path") != "/":
                raise PublishError("Pages was concurrently enabled with a different source; preserving it") from error
    else:
        _, pages = api_request(token, "GET", f"/repos/{REPOSITORY}/pages")

    base_url = pages.get("html_url") or f"https://geekaudio.github.io/itlwm/"
    source_root = source_path.strip("/")
    public_prefix = prefix[len(source_root):].strip("/") if source_root and prefix.startswith(source_root) else prefix
    public_root = urllib.parse.urljoin(base_url.rstrip("/") + "/", (public_prefix + "/") if public_prefix else "")
    readback: dict[str, str] = {}
    for attempt in range(10):
        try:
            for relative in FILES:
                # A read made while Pages is still building can cache the
                # preceding HTML. Give each verification a fresh cache key.
                url = (urllib.parse.urljoin(public_root, relative) + "?v=" + commit[:12]
                       + "&verify=" + str(time.time_ns()))
                remote_data = public_get(url)
                if sha256(remote_data) != hashes[relative]:
                    raise PublishError(f"Public asset hash does not match local build: {relative}")
                readback[relative] = sha256(remote_data)
            break
        except (urllib.error.URLError, TimeoutError, PublishError) as error:
            if attempt == 9:
                raise PublishError(f"Public readback did not match after retries: {error}") from error
            time.sleep(10)

    final_url = urllib.parse.urljoin(public_root, "milestones.html")
    state_value = {
        "repository": REPOSITORY,
        "branch": BRANCH,
        "branch_prefix": prefix,
        "last_commit": commit,
        "files": hashes,
        "public_url": final_url,
    }
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state_value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = {
        "repository": REPOSITORY,
        "branch": BRANCH,
        "commit": commit,
        "changed": changed,
        "page_url": final_url,
        "published_label": data.get("validationLabel"),
        "running_candidate": data.get("runningCandidate"),
        "next_candidate": next_candidate,
        "deployment_state": data.get("deploymentState"),
        "pages_build_status": pages.get("status"),
        "current_validation": {
            "passed": sum(check.get("current_result") == "passed"
                          for milestone in data.get("milestones", [])
                          for check in milestone.get("checkpoints", [])),
            "total": data.get("progressModel", {}).get("fixed_total"),
            "scope": "current_runtime_only",
        },
        "allowlisted_files": hashes,
        "public_readback_sha256": readback,
        "public_readback_verified": True,
        "pages_source": {"branch": BRANCH, "path": source_path},
    }
    report_path = RESEARCH / f"github-pages-{page_candidate.lower()}-publish-private.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "published_and_readback_verified", "page_url": final_url,
                      "commit": commit, "changed": changed,
                      "running_candidate": data.get("runningCandidate"),
                      "next_candidate": next_candidate,
                      "deployment_state": data.get("deploymentState"),
                      "pages_build_status": pages.get("status")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PublishError as error:
        print(f"publish stopped safely: {error}", file=sys.stderr)
        raise SystemExit(1)
