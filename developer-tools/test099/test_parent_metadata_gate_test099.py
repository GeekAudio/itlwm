#!/usr/bin/env python3
"""Exercise Test099's real parent-process metadata gate with its helper binding."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

import controlled_run_test099 as controlled


class ParentMetadataGateTests(unittest.TestCase):
    def test_test099_profile_binds_the_real_test099_helper(self) -> None:
        metadata = json.loads(controlled.DEFAULT_METADATA.read_text(encoding="utf-8"))
        receipt_sha = hashlib.sha256(controlled.BUILD_RECEIPT.read_bytes()).hexdigest()
        boot_epoch = metadata["minimum_boot_epoch_exclusive"] + 1

        # This is the same validator used by Test087's coordinator after the
        # Test099 native worker reports READY, not a mock of the parent gate.
        before = controlled.PROTOCOL.validate_private_metadata(
            metadata,
            boot_epoch=boot_epoch,
            expected_receipt_sha256=receipt_sha,
            actual_receipt_sha256=receipt_sha,
        )
        self.assertIn("arm_helper_source_hash", before)

        old_helper_source = controlled.PROTOCOL.HELPER_SOURCE
        restore = controlled.configure_test099_profile()
        try:
            self.assertEqual(controlled.PROTOCOL.HELPER_SOURCE,
                             controlled.ARM_HELPER)
            after = controlled.PROTOCOL.validate_private_metadata(
                metadata,
                boot_epoch=boot_epoch,
                expected_receipt_sha256=receipt_sha,
                actual_receipt_sha256=receipt_sha,
            )
            self.assertEqual(after, [])
        finally:
            restore()

        self.assertEqual(controlled.PROTOCOL.HELPER_SOURCE, old_helper_source)


if __name__ == "__main__":
    unittest.main()
