import hashlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PublicPackageTest(unittest.TestCase):
    def test_sha256_manifest_covers_exact_source_tree(self):
        checksum_file = ROOT / "SHA256SUMS.txt"
        self.assertTrue(checksum_file.is_file())
        recorded = {}
        for line in checksum_file.read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            path = Path(name)
            self.assertFalse(path.is_absolute())
            self.assertNotIn("..", path.parts)
            self.assertNotIn(name, recorded)
            recorded[name] = digest

        actual = {
            path.relative_to(ROOT).as_posix()
            for path in ROOT.rglob("*")
            if path.is_file() and path != checksum_file
            and "__pycache__" not in path.parts
        }
        self.assertEqual(set(recorded), actual)
        for name, digest in recorded.items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest, name)

    def test_package_contains_no_runtime_or_private_artifacts(self):
        paths = [path for path in ROOT.rglob("*") if path.is_file()]
        forbidden = {".ko", ".pcap", ".pcapng", ".log", ".zip"}
        for path in paths:
            self.assertNotIn(path.suffix.lower(), forbidden, str(path))
        public_json = {
            path.relative_to(ROOT).as_posix()
            for path in paths if path.suffix.lower() == ".json"
        }
        self.assertEqual(public_json, {"PATCH-MANIFEST.json"})


if __name__ == "__main__":
    unittest.main()
