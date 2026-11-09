"""File-boundary fixtures for coordinator tests; never an executable tool."""
import hashlib
import json
from pathlib import Path
import tempfile
from unittest import mock


def configure(coordinator):
    """Keep the real adapter setup without depending on private build caches.

    Temporary copies of source files stand in for already-validated binary
    artifacts. Nothing executes them; real hash/adapter/provenance code still
    runs against real bytes. The private location preserves the two hash keys
    (private artifact and T104 repository anchor) used by production. Artifact
    receipt validation itself has separate negative tests. The caller owns the
    returned TemporaryDirectory and must register its cleanup.
    """
    def artifact(path):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return {"binary_path": str(path), "binary_sha256": digest,
                "source_sha256": digest}

    runner = coordinator.RUNNER
    runner.REPO = coordinator.BINDING.IWN_ROOT.resolve(strict=True)
    temporary = tempfile.TemporaryDirectory(
        prefix=".test123-offline-artifacts-", dir=runner.REPO)
    try:
        fixture_root = Path(temporary.name)
        sender = fixture_root / "iwldual_sender_test123"
        listener = fixture_root / "awdl0_unicast_listener_test123"
        sender.write_bytes(coordinator.SENDER_SOURCE.read_bytes())
        listener.write_bytes(coordinator.LISTENER_SOURCE.read_bytes())
        sender_record = artifact(sender)
        listener_record = artifact(listener)
        receipt = fixture_root / "sender-build-fixture.json"
        receipt.write_text(json.dumps(sender_record, sort_keys=True) + "\n")
        receipt.chmod(0o600)
        runner.SENDER_BINARY = sender
        coordinator.KERNEL_COORDINATOR._bind_test121_profile_router_alias()
        with mock.patch.object(coordinator.KERNEL_COORDINATOR,
                               "_configure_test122_run"), \
                mock.patch.object(coordinator, "_validated_tool_artifacts",
                                  return_value=(sender_record, listener_record)), \
                mock.patch.object(runner, "runtime_tool_hashes", return_value={}):
            coordinator._configure_test123_run()
            # Setup installs a closure; retain it after patch restoration so
            # run_once still hashes the actual source and fixture artifacts.
            configured_hashes = runner.runtime_tool_hashes
        runner.runtime_tool_hashes = configured_hashes
        runner.SENDER_BUILD_RECEIPT = receipt
        runner.sender_receipt = lambda _uid: json.loads(receipt.read_text())
        return temporary
    except BaseException:
        temporary.cleanup()
        raise
