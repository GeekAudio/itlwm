"""Host-only nonce-ledger ownership and no-reuse regressions."""
from pathlib import Path
import json
import os
import tempfile
import unittest
from unittest import mock

import rx149_binding_test123 as binding


class PrivateOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tool123-owner-")
        self.base = Path(self.temp.name).resolve()
        self.ledger = self.base / "ledger"
        self.nonce = "1234567890abcdef"
        self.digest = "a" * 64
        self.token = "b" * 32

    def tearDown(self):
        self.temp.cleanup()

    def claim(self):
        return binding._claim_wire_nonce(
            self.ledger, self.nonce, self.digest, self.token)

    def test_owner_reservation_is_private_and_keeps_legacy_ledger_contract(self):
        path = self.claim()
        self.assertEqual(path.name, self.nonce + ".json")
        value = json.loads(path.read_text())
        self.assertEqual(value["schema"], "test122-wire-nonce-claim/v1")
        self.assertEqual(value["state"], "reserved_before_device_io")
        self.assertEqual(value["run_token"], self.token)
        self.assertEqual(path.stat().st_uid, binding.REPO_ROOT.stat().st_uid)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.ledger.stat().st_mode & 0o777, 0o700)

    def test_root_execution_assigns_only_new_objects_to_workspace_owner(self):
        # Simulate root's branch without elevating this test process or
        # changing real file owners. The real fchown arguments are verified.
        uid, gid = binding._workspace_ids()
        with mock.patch.object(binding.os, "geteuid", return_value=0), \
                mock.patch.object(binding.os, "chown") as chown, \
                mock.patch.object(binding.os, "fchown") as fchown:
            self.claim()
        chown.assert_called_once_with(self.ledger, uid, gid, follow_symlinks=False)
        self.assertEqual(fchown.call_count, 1)
        self.assertEqual(fchown.call_args.args[1:], (uid, gid))

    def test_existing_nonce_is_never_reassigned_or_overwritten_by_root(self):
        path = self.claim()
        original = path.read_bytes()
        self.token = "c" * 32
        with mock.patch.object(binding.os, "geteuid", return_value=0), \
                mock.patch.object(binding.os, "chown") as chown, \
                mock.patch.object(binding.os, "fchown") as fchown:
            with self.assertRaisesRegex(binding.Tool123BindingError,
                                        "wire_nonce_already_claimed"):
                self.claim()
        chown.assert_not_called()
        fchown.assert_not_called()
        self.assertEqual(path.read_bytes(), original)

    def test_existing_unsafe_directory_is_rejected_not_repaired(self):
        self.ledger.mkdir(mode=0o755)
        self.ledger.chmod(0o755)
        with self.assertRaisesRegex(binding.Tool123BindingError, "mode_or_owner"):
            self.claim()
        self.assertEqual(self.ledger.stat().st_mode & 0o777, 0o755)
        self.assertEqual(list(self.ledger.iterdir()), [])

    def test_symlink_and_symlink_parent_do_not_create_claim(self):
        actual = self.base / "actual"
        actual.mkdir(mode=0o700)
        self.ledger.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(binding.Tool123BindingError):
            self.claim()
        self.ledger = self.ledger / "child"
        with self.assertRaises(binding.Tool123BindingError):
            self.claim()
        self.assertEqual(list(actual.iterdir()), [])

    def test_unrelated_executor_cannot_create_private_directory(self):
        with mock.patch.object(binding.os, "geteuid", return_value=os.getuid() + 1000):
            with self.assertRaisesRegex(binding.Tool123BindingError, "executor_not"):
                self.claim()
        self.assertFalse(self.ledger.exists())

    def test_invalid_wire_identity_is_rejected_before_writing(self):
        for bad in ("0" * 16, "../other", "A" * 16, "short"):
            self.nonce = bad
            with self.subTest(nonce=bad), self.assertRaises(binding.Tool123BindingError):
                self.claim()
        self.assertFalse(self.ledger.exists())


if __name__ == "__main__":
    unittest.main()
