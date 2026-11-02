import json
import unittest
from openwrt_echo_ready import FIXED, contract_digest, normalize, validate_live_line


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.identity = dict(run_token="12"*16, nonce="34"*8,
                             local_mac="02:00:00:00:00:01", peer_mac="02:00:00:00:00:02",
                             local_ipv6="fe80::1", peer_ipv6="fe80::2")
        self.ready = dict(schema="test110-openwrt-echo-peer/v1", event="READY",
                          **self.identity, **FIXED, window_ms=16000, ifindex=8,
                          monotonic_start_ns=100, monotonic_deadline_ns=16000000100,
                          token_bytes_hex=self.identity["run_token"])

    def line(self):
        return (json.dumps(self.ready)+"\n").encode()

    def test_fixed_live_contract(self):
        value = validate_live_line(self.line(), self.identity, 300)
        self.assertEqual(value["window_ms"], 15700)
        self.assertEqual(value["local_mac"], "020000000001")
        self.assertEqual(value["contract_identity_digest"], contract_digest(normalize(self.identity)))
        self.assertNotIn("created_utc", value)  # Only a live child adds creation time.

    def test_identity_mismatch(self):
        for key, value in (("nonce", "56"*8), ("run_token", "78"*16),
                           ("peer_mac", "02:00:00:00:00:03"), ("local_ipv6", "fe80::3")):
            original = self.ready[key]; self.ready[key] = value
            with self.assertRaises(ValueError): validate_live_line(self.line(), self.identity, 0)
            self.ready[key] = original

    def test_bounds_and_duplicate(self):
        for elapsed in (-1, 10000, 16000, True):
            with self.assertRaises(ValueError): validate_live_line(self.line(), self.identity, elapsed)
        for key, value in (("channel", True), ("channel", 149), ("window_ms", 16001),
                           ("monotonic_deadline_ns", 17000000100), ("event", "RESULT")):
            original = self.ready[key]; self.ready[key] = value
            with self.assertRaises(ValueError): validate_live_line(self.line(), self.identity, 1)
            self.ready[key] = original
        with self.assertRaises(ValueError):
            validate_live_line(self.line().replace(b'{', b'{"event":"READY",', 1), self.identity, 1)


if __name__ == "__main__": unittest.main()
