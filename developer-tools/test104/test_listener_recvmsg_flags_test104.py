#!/usr/bin/env python3
"""Verify Darwin recvmsg truncation flags with the listener's 4 KiB buffer."""
from __future__ import annotations

import select
import socket
import unittest


BUFFER_SIZE = 4096
MARKER = b"T086RX01"


def receive_after_poll(receiver: socket.socket):
    poller = select.poll()
    poller.register(receiver.fileno(), select.POLLIN)
    if not poller.poll(1000):
        raise AssertionError("loopback UDP datagram did not arrive")
    return receiver.recvmsg(BUFFER_SIZE, 0, socket.MSG_DONTWAIT)


class ListenerRecvmsgFlagsTests(unittest.TestCase):
    def exchange(self, payload: bytes):
        receiver = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sender = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            receiver.bind(("::1", 0))
            sender.sendto(payload, receiver.getsockname())
            return receive_after_poll(receiver)
        finally:
            sender.close()
            receiver.close()

    def test_complete_marker_does_not_report_payload_truncation(self):
        data, ancillary, flags, _ = self.exchange(MARKER)
        self.assertEqual(ancillary, [])
        self.assertEqual(data, MARKER)
        self.assertEqual(len(data), len(MARKER))
        self.assertFalse(flags & socket.MSG_TRUNC)

    def test_real_oversize_datagram_keeps_truncation_rejection(self):
        data, ancillary, flags, _ = self.exchange(b"X" * (BUFFER_SIZE + 1))
        self.assertEqual(ancillary, [])
        self.assertEqual(len(data), BUFFER_SIZE)
        self.assertTrue(flags & socket.MSG_TRUNC)


if __name__ == "__main__":
    unittest.main()
