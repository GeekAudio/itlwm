#!/usr/bin/env python3
"""Ensure Test070-only types and fields disappear when discovery is disabled."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOKEN_GROUPS = {
    ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp": ("mifBootstrap", "Test070MifBootstrap"),
    ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.hpp": (
        "TahoeP2PActionTxControlSubmitFence", "kControlSubmitFence"),
    ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp": (
        "controlSubmitFence", "TahoeP2PActionTxControlSubmitFence",
        "kControlSubmitFence"),
}


def is_discovery_directive(directive):
    return "ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332" in directive


def check_file(path, tokens):
    stack = []
    discovery_enabled = False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith(("//", "/*", "*")):
            continue
        if stripped.startswith("#if ") or stripped.startswith("#ifdef ") or stripped.startswith("#ifndef "):
            expr = stripped.split(None, 1)[1] if " " in stripped else ""
            parent = discovery_enabled
            if is_discovery_directive(expr):
                positive = not expr.lstrip().startswith("!defined") and not expr.startswith("#ifndef")
                branch = positive
                stack.append(("discovery", parent, branch, positive))
                discovery_enabled = branch
            else:
                stack.append(("other", parent, discovery_enabled, True))
            continue
        if stripped.startswith("#elif "):
            if not stack:
                raise AssertionError(f"unmatched #elif at {path}:{number}")
            kind, parent, _branch, first = stack.pop()
            expr = stripped.split(None, 1)[1]
            if is_discovery_directive(expr):
                positive = not expr.lstrip().startswith("!defined")
                branch = not first and positive
                stack.append(("discovery", parent, branch, first or positive))
                discovery_enabled = branch
            else:
                stack.append((kind, parent, discovery_enabled, first))
            continue
        if stripped == "#else":
            if not stack:
                raise AssertionError(f"unmatched #else at {path}:{number}")
            kind, parent, _branch, first = stack.pop()
            branch = not first if kind == "discovery" else parent
            stack.append((kind, parent, branch, True))
            discovery_enabled = branch
            continue
        if stripped.startswith("#endif"):
            if not stack:
                raise AssertionError(f"unmatched #endif at {path}:{number}")
            _kind, parent, _branch, _first = stack.pop()
            discovery_enabled = parent
            continue
        if any(token in line for token in tokens) and not discovery_enabled:
            raise AssertionError(
                f"Test070-only reference escapes discovery guard at {path}:{number}: {line.strip()}")
    if stack:
        raise AssertionError(f"unterminated preprocessor block in {path}")


def main():
    for path, tokens in TOKEN_GROUPS.items():
        check_file(path, tokens)
    print("PASS: Test070 fields, API, and helper branches are discovery-macro guarded")


if __name__ == "__main__":
    main()
