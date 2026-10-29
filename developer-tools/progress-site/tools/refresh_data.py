#!/usr/bin/env python3
"""Project a safe, small subset of the local milestone JSON into static JS."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "research" / "milestones-current.json"
TARGET = ROOT / "progress-site" / "dist" / "data.js"
TEXT_FIELDS = ("name", "status", "evidence", "pending", "acceptance")
OPTIONAL_TEXT_FIELDS = ("validated_scope", "candidate_check", "change_note", "current_summary", "unfinished_summary", "current_result_label")
RESTRICTED_VALUE_PATTERNS = (
    re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])"),
    re.compile(r"(?i)\b(?:ssid|bssid)\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(?:api[_ -]?)?token\s*[:=]\s*\S+"),
    re.compile(r"(?:^|\s)(?:/Users/|/Volumes/|/private/|[A-Za-z]:\\)"),
)


def safe_summary(value: object, stage: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Expected summary text for stage {stage}, field {field}")
    if "\n" in value or "\r" in value:
        raise ValueError(f"Refusing multiline content for stage {stage}, field {field}")
    if any(pattern.search(value) for pattern in RESTRICTED_VALUE_PATTERNS):
        raise ValueError(f"Refusing potentially private content for stage {stage}, field {field}")
    return value


def main() -> None:
    raw = json.loads(SOURCE.read_text(encoding="utf-8"))
    updated_at = raw.get("updated_at")
    if not isinstance(updated_at, str):
        raise ValueError("Refusing a project snapshot without an ISO timestamp")
    try:
        datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Refusing an invalid project snapshot timestamp") from error
    milestones = []
    for milestone in raw.get("milestones", []):
        stage = milestone.get("stage")
        if not isinstance(stage, int):
            raise ValueError("Refusing a milestone without a numeric stage")
        safe = {"stage": stage}
        for field in TEXT_FIELDS:
            safe[field] = safe_summary(milestone.get(field, ""), stage, field)
        for field in OPTIONAL_TEXT_FIELDS:
            if field in milestone:
                safe[field] = safe_summary(milestone[field], stage, field)
        for field in ("has_runtime_evidence", "has_pending_work"):
            if field in milestone:
                if type(milestone[field]) is not bool:
                    raise ValueError(f"Expected boolean for stage {stage}, field {field}")
                safe[field] = milestone[field]
        if "status_tone" in milestone:
            if milestone["status_tone"] not in ("success", "working", "pending", "warning"):
                raise ValueError(f"Invalid status tone for stage {stage}")
            safe["status_tone"] = milestone["status_tone"]
        verdicts = ("passed", "regressed", "partial", "not_covered", "not_implemented")
        if "current_result" in milestone:
            if milestone["current_result"] not in verdicts:
                raise ValueError("Invalid current result")
            safe["current_result"] = milestone["current_result"]
        if "checkpoints" in milestone:
            checkpoints = milestone["checkpoints"]
            if not isinstance(checkpoints, list) or len(checkpoints) != 5:
                raise ValueError("Acceptance model v1 requires five checks per stage")
            safe["checkpoints"] = []
            for checkpoint in checkpoints:
                if checkpoint.get("current_result") not in verdicts:
                    raise ValueError("Invalid checkpoint result")
                clean = {field: safe_summary(checkpoint.get(field, ""), stage, field)
                         for field in ("id", "name", "current_detail")}
                clean.update(current_result=checkpoint["current_result"])
                historical = checkpoint.get("history_verified", False)
                if type(historical) is not bool:
                    raise ValueError("Invalid historical verification flag")
                clean["history_verified"] = historical
                if "verified_in" in checkpoint:
                    clean["verified_in"] = safe_summary(checkpoint["verified_in"], stage, "verified_in")
                safe["checkpoints"].append(clean)
        milestones.append(safe)

    data = {
        "updatedAt": updated_at,
        "runningCandidate": raw.get("running_candidate"),
        "nextCandidate": raw.get("next_candidate"),
        "deploymentState": raw.get("deployment_state"),
        "milestones": milestones,
        "progressModel": {"version": "current-runtime-v2", "fixed_total": 40,
                          "meaning": safe_summary(raw.get("progress_model", {}).get(
                              "meaning", "当前启动的实机验收；未覆盖项不计通过，历史覆盖单独展示。"),
                              "project", "progress_model_meaning")},
    }
    for field in ("runningCandidate", "nextCandidate", "deploymentState"):
        value = data[field]
        if value is not None:
            data[field] = safe_summary(value, "project", field)
    if "validation_label" in raw:
        data["validationLabel"] = safe_summary(raw["validation_label"], "project", "validation_label")
    for source, target in (("next_candidate_state", "nextCandidateState"),
                           ("next_candidate_summary", "nextCandidateSummary"),
                           ("current_runtime_label", "currentRuntimeLabel"),
                           ("current_record_role", "currentRecordRole"),
                           ("next_candidate_role", "nextCandidateRole"),
                           ("evidence_scope_label", "evidenceScopeLabel")):
        if source in raw:
            data[target] = safe_summary(raw[source], "project", source)
    if "workflow" in raw:
        flow = raw["workflow"]
        if not isinstance(flow, dict) or flow.get("candidate") != raw.get("running_candidate"):
            raise ValueError("Workflow evidence must match the running candidate")
        clean_flow = {field: safe_summary(flow.get(field, ""), "workflow", field)
                      for field in ("candidate", "phaseLabel", "headline", "summary", "nextAction")}
        primary = flow.get("primaryStage")
        if type(primary) is not int or not 1 <= primary <= 8:
            raise ValueError("Workflow must identify a valid milestone stage")
        clean_flow["primaryStage"] = primary
        steps = flow.get("steps")
        if not isinstance(steps, list) or not 1 <= len(steps) <= 8:
            raise ValueError("Workflow must contain a bounded list of steps")
        clean_flow["steps"] = []
        for step in steps:
            stage = step.get("stage")
            if type(stage) is not int or not 1 <= stage <= 8:
                raise ValueError("Workflow step has an invalid stage")
            if step.get("status") not in ("verified", "blocked", "waiting", "partial", "attention"):
                raise ValueError("Invalid workflow step status")
            clean = {field: safe_summary(step.get(field, ""), "workflow", field)
                     for field in ("id", "title", "detail", "status")}
            clean["stage"] = stage
            clean_flow["steps"].append(clean)
        facts = flow.get("facts", [])
        if not isinstance(facts, list) or len(facts) > 8:
            raise ValueError("Workflow facts exceed the bounded summary")
        clean_flow["facts"] = [{field: safe_summary(fact.get(field, ""), "workflow", field)
                                for field in ("label", "value")} for fact in facts]
        if flow.get("alert"):
            alert = flow["alert"]
            stage = alert.get("stage")
            if type(stage) is not int or not 1 <= stage <= 8:
                raise ValueError("Workflow alert has an invalid stage")
            clean_flow["alert"] = {field: safe_summary(alert.get(field, ""), "workflow", field)
                                   for field in ("title", "detail")}
            clean_flow["alert"]["stage"] = stage
        data["workflow"] = clean_flow
    timeline = raw.get("timeline")
    if isinstance(timeline, dict) and timeline.get("scope") == "project":
        scope = "project"
        title = safe_summary(timeline.get("title", "开发总时间线"), "timeline", "title")
        summary = safe_summary(timeline.get("summary", ""), "timeline", "summary")
        candidate = timeline.get("candidate")
        if candidate is not None:
            candidate = safe_summary(candidate, "timeline", "candidate")
        steps = timeline.get("steps")
        if not isinstance(steps, list) or not 1 <= len(steps) <= 128:
            raise ValueError("Project timeline must contain 1 to 128 key steps")
        clean_steps = []
        order = {"done": 0, "current": 1, "pending": 2}
        previous_order = -1
        current_count = 0
        for step in steps:
            if not isinstance(step, dict):
                raise ValueError("Timeline step must be an object")
            status = step.get("status")
            if status not in order:
                raise ValueError("Invalid current timeline status")
            if order[status] < previous_order:
                raise ValueError("Timeline statuses must progress from done to current to pending")
            previous_order = order[status]
            current_count += status == "current"
            clean = {
                "id": safe_summary(step.get("id", ""), "timeline", "id"),
                "label": safe_summary(step.get("label", ""), "timeline", "label"),
                "status": status,
                "detail": safe_summary(step.get("detail", ""), "timeline", "detail"),
            }
            if not clean["id"] or not clean["label"]:
                raise ValueError("Timeline step needs a stable id and label")
            state_label = step.get("stateLabel")
            if state_label is not None:
                clean["stateLabel"] = safe_summary(state_label, "timeline", "stateLabel")
            if status == "done" and not clean.get("stateLabel"):
                raise ValueError("Completed project milestones need an event-specific stateLabel")
            step_candidate = step.get("candidate")
            if step_candidate is not None:
                clean["candidate"] = safe_summary(step_candidate, "timeline", "step candidate")
            timestamp = step.get("time")
            if status == "pending":
                # A planned step is not an observed timestamp.
                clean["time"] = None
            elif timestamp is not None:
                if not isinstance(timestamp, str):
                    raise ValueError("Timeline time must be an ISO date, datetime, or null")
                if re.fullmatch(r"\d{4}-\d{2}-\d{2}", timestamp):
                    try:
                        datetime.strptime(timestamp, "%Y-%m-%d")
                    except ValueError as error:
                        raise ValueError("Invalid timeline date") from error
                else:
                    try:
                        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    except ValueError as error:
                        raise ValueError("Invalid timeline datetime") from error
                clean["time"] = safe_summary(timestamp, "timeline", "time")
            else:
                clean["time"] = None
            stage = step.get("stage")
            if stage is not None:
                if isinstance(stage, str):
                    match = re.fullmatch(r"stage-([1-8])", stage)
                    if not match:
                        raise ValueError("Timeline step has an invalid milestone stage")
                    stage = int(match.group(1))
                if type(stage) is not int or not 1 <= stage <= 8:
                    raise ValueError("Timeline step has an invalid milestone stage")
                clean["stage"] = stage
            clean_steps.append(clean)
        if current_count > 1:
            raise ValueError("Current timeline can have at most one active step")
        data["timeline"] = {"scope": scope, "title": title, "summary": summary, "steps": clean_steps}
        if candidate is not None:
            data["timeline"]["candidate"] = candidate
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(
        "window.PROGRESS_DATA = "
        + json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        + ";\n",
        encoding="utf-8",
    )
    # Keep a self-contained copy that can be opened directly after a reboot.
    dist = TARGET.parent
    page = (dist / "index.html").read_text(encoding="utf-8")
    css = (dist / "assets/site.css").read_text(encoding="utf-8")
    page = page.replace('<link rel="stylesheet" href="./assets/site.css">',
                        "<style>\n" + css + "\n</style>")
    scripts = []
    for asset in ("data.js", "assets/test-records.js", "assets/site.js"):
        page = page.replace(f'<script src="./{asset}" defer></script>', "")
        script = (dist / asset).read_text(encoding="utf-8")
        scripts.append("<script>\n" + script.replace("</script", "<\\/script") + "\n</script>")
    page = page.replace("</body>", "\n".join(scripts) + "\n</body>")
    (dist / "milestones.html").write_text(page, encoding="utf-8")
    print("Updated project data and standalone milestones.html")
    if os.environ.get("INTELWIRELESS_PAGES_PUBLISHER_ACTIVE") != "1":
        publisher = ROOT / "progress-site" / "tools" / "publish_github_pages.py"
        print("Publishing the allowlisted milestone site to GitHub Pages")
        subprocess.run([sys.executable, str(publisher)], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
