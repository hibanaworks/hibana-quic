"""The local network fixture must apply its advertised mutations faithfully."""
import socket
import time
import unittest
from udp_impairment import UdpProxy, EarlyWireProbe


class ProxyTests(unittest.TestCase):
    def exchange(self, **options):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            server.settimeout(1)
            with UdpProxy(server.getsockname(), **options) as proxy:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(1)
                    started = time.monotonic()
                    client.sendto(b'fixture', proxy.address)
                    data, peer = server.recvfrom(100)
                    server.sendto(data, peer)
                    returned, _ = client.recvfrom(100)
                    elapsed = time.monotonic() - started
                return data, returned, elapsed, dict(proxy.stats)

    def test_forward_and_return(self):
        data, returned, _, stats = self.exchange()
        self.assertEqual((data, returned), (b'fixture', b'fixture'))
        self.assertEqual(stats['to_server_forwarded'], 1)
        self.assertEqual(stats['to_client_forwarded'], 1)

    def test_delay_is_in_each_direction(self):
        _, _, elapsed, _ = self.exchange(delay=0.03)
        self.assertGreaterEqual(elapsed, 0.06)

    def test_corruption_occurs_in_both_directions(self):
        data, returned, _, stats = self.exchange(corrupt_every=1)
        self.assertNotEqual(data, b'fixture')
        self.assertEqual(returned, b'fixture')
        self.assertEqual(stats['to_server_corrupted'], 1)
        self.assertEqual(stats['to_client_corrupted'], 1)

    def test_loss_does_not_forward_selected_packet(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            server.settimeout(0.15)
            with UdpProxy(server.getsockname(), drop_every=1) as proxy:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.sendto(b'lost', proxy.address)
                    with self.assertRaises(socket.timeout):
                        server.recvfrom(100)
                self.assertEqual(proxy.stats['to_server_dropped'], 1)
                self.assertEqual(proxy.stats['to_server_forwarded'], 0)


class WireProbeTests(unittest.TestCase):
    def test_coalesced_packet_lengths_and_datagram_zero_suffix(self):
        initial = b"\xc0\x00\x00\x00\x01\x00\x00\x00\x04" + b"abcd"
        early = b"\xd0\x00\x00\x00\x01\x00\x00\x04" + b"efgh"
        self.assertEqual(EarlyWireProbe.packet_lengths(initial + early + bytes(7)),
                         [('initial', len(initial)), ('zero_rtt', len(early)), ('trailing_zero_bytes', 7)])

    def test_protected_payload_bound_keeps_pn_tag_and_padding(self):
        self.assertEqual(EarlyWireProbe.short_payload_upper_bound(b"\x43server01" + bytes(31), {b"server01"}), 31)
        with self.assertRaises(ValueError):
            EarlyWireProbe.short_payload_upper_bound(b"\x43othercid" + bytes(31), {b"server01"})

    def test_short_packet_counts_all_remaining_bytes(self):
        self.assertEqual(EarlyWireProbe.packet_lengths(b"\x43" + bytes(30)), [('one_rtt', 31)])

    def test_nonzero_unclassified_suffix_is_not_silently_ignored(self):
        initial = b"\xc0\x00\x00\x00\x01\x00\x00\x00\x04" + b"abcd"
        with self.assertRaises(ValueError):
            EarlyWireProbe.packet_lengths(initial + b"\x00\x01")


if __name__ == '__main__':
    unittest.main()
