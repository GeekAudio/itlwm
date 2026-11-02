import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

SITE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("render_site", SITE / "tools/render_site.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


class AtomicSnapshotTests(unittest.TestCase):
    def test_content_revision_and_self_contained_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = Path(tmp)
            shutil.copytree(SITE / "templates", site / "templates")
            (site / "dist/assets").mkdir(parents=True)
            for name in renderer.ASSETS:
                shutil.copy2(SITE / "dist" / name, site / "dist" / name)
            first = renderer.render_site(site, "2026-11-02T16:00:00+08:00")
            self.assertEqual(first, renderer.render_site(site, "2026-11-02T16:00:00+08:00"))
            entry = (site / "dist/milestones.html").read_text()
            self.assertEqual(entry, (site / "dist/index.html").read_text())
            self.assertNotIn('<script src="./data.js"', entry)
            self.assertNotIn('<link rel="stylesheet" href="./assets/site.css">', entry)
            with (site / "dist/data.js").open("a") as f:
                f.write("\n// a newly published snapshot\n")
            second = renderer.render_site(site, "2026-11-02T16:01:00+08:00")
            self.assertNotEqual(first, second)
            manifest = json.loads((site / "dist/site-version.json").read_text())
            self.assertEqual(manifest["version"], second)
            for name, digest in manifest["files"].items():
                self.assertEqual(hashlib.sha256((site / "dist" / name).read_bytes()).hexdigest(), digest)
            self.assertIn(second, (site / "dist/milestones.html").read_text())


if __name__ == "__main__":
    unittest.main()
