#!/usr/bin/env python3
"""Build gate rejects unresolved C++ anonymous-namespace symbols."""

from pathlib import Path
import importlib.util
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "tahoe_builder_test110_symbols", ROOT / "scripts/build_tahoe.py"
)
assert SPEC and SPEC.loader
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class UnresolvedInternalSymbolGate(unittest.TestCase):
    def test_rejects_nested_anonymous_namespace_symbol(self):
        undefined = (
            "                 (undefined) external "
            "__ZN12_GLOBAL__N_112_GLOBAL__N_134drainDirectedDataRxOutsideMainGateE"
            "PN12_GLOBAL__N_111P2PProbeRunERKNS_11RocEventRunE (dynamically looked up)"
        )
        self.assertEqual(BUILDER.unresolved_project_symbols(undefined), [undefined.strip()])

    def test_rejects_project_symbol_even_without_anonymous_namespace(self):
        undefined = "(undefined) external __ZN6ItlIwx10setKeyCallEv"
        self.assertEqual(BUILDER.unresolved_project_symbols(undefined), [undefined])

    def test_allows_expected_kernel_and_apple_imports(self):
        undefined = "\n".join((
            "(undefined) external _IOLog (dynamically looked up)",
            "(undefined) external _IOMalloc (dynamically looked up)",
            "(undefined) external __ZN8OSObjectdlEv (dynamically looked up)",
        ))
        self.assertEqual(BUILDER.unresolved_project_symbols(undefined), [])


if __name__ == "__main__":
    unittest.main()
