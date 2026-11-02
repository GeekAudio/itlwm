#!/usr/bin/env python3
"""Subprocess tests for refresh_data.py command-line side effects."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SOURCE_SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "refresh_data.py"


def tree_snapshot(root: Path) -> dict[str, tuple]:
    """Capture paths, contents, and mtimes so attempted writes are visible."""
    result = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        stat = path.stat()
        if path.is_dir():
            result[relative] = ("directory", stat.st_mtime_ns)
        else:
            result[relative] = (
                "file",
                stat.st_mtime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
    return result


class RefreshDataCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="refresh-data-cli-")
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        self.root = self.workspace / "developer-tools"
        self.tool_dir = self.root / "progress-site" / "tools"
        self.dist = self.root / "progress-site" / "dist"
        self.assets = self.dist / "assets"
        self.research = self.root / "research"
        self.tool_dir.mkdir(parents=True)
        self.assets.mkdir(parents=True)
        self.research.mkdir()

        self.script = self.tool_dir / "refresh_data.py"
        shutil.copy2(SOURCE_SCRIPT, self.script)
        (self.research / "milestones-current.json").write_text(
            json.dumps(
                {
                    "updated_at": "2026-11-02T00:00:00+08:00",
                    "running_candidate": "25G332-Test111",
                    "milestones": [],
                }
            ),
            encoding="utf-8",
        )
        (self.dist / "index.html").write_text(
            '<html><head><link rel="stylesheet" href="./assets/site.css"></head>'
            '<body><script src="./data.js" defer></script>'
            '<script src="./assets/test-records.js" defer></script>'
            '<script src="./assets/site.js" defer></script></body></html>',
            encoding="utf-8",
        )
        (self.assets / "site.css").write_text("body { color: #222; }", encoding="utf-8")
        (self.assets / "test-records.js").write_text(
            "window.TEST_RECORDS = [];", encoding="utf-8"
        )
        (self.assets / "site.js").write_text("window.siteLoaded = true;", encoding="utf-8")
        # A harmless publisher spy proves whether generation reaches the publish step.
        (self.tool_dir / "publish_github_pages.py").write_text(
            "from pathlib import Path\n"
            "Path('publisher-called.marker').write_text('called', encoding='utf-8')\n",
            encoding="utf-8",
        )

        self.environment = os.environ.copy()
        self.environment.pop("INTELWIRELESS_PAGES_PUBLISHER_ACTIVE", None)

    def run_script(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(self.script), *arguments],
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_help_exits_successfully_without_writing_or_publishing(self) -> None:
        before = tree_snapshot(self.workspace)

        result = self.run_script("--help")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage:", result.stdout.lower())
        self.assertEqual(tree_snapshot(self.workspace), before)
        self.assertFalse((self.root / "publisher-called.marker").exists())

    def test_unknown_argument_is_rejected_without_writing_or_publishing(self) -> None:
        before = tree_snapshot(self.workspace)

        result = self.run_script("--unexpected-option")

        self.assertEqual(result.returncode, 2)
        self.assertIn("unrecognized arguments: --unexpected-option", result.stderr)
        self.assertEqual(tree_snapshot(self.workspace), before)
        self.assertFalse((self.root / "publisher-called.marker").exists())

    def test_no_arguments_still_generates_and_invokes_publisher(self) -> None:
        result = self.run_script()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Updated project data and standalone milestones.html", result.stdout)
        self.assertTrue((self.dist / "data.js").is_file())
        self.assertTrue((self.dist / "milestones.html").is_file())
        self.assertEqual(
            (self.root / "publisher-called.marker").read_text(encoding="utf-8"),
            "called",
        )


if __name__ == "__main__":
    unittest.main()
