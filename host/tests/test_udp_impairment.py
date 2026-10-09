"""The local network fixture must apply its advertised mutations faithfully."""
import socket
import time
import unittest
from unittest.mock import patch, Mock
from udp_impairment import UdpProxy, EarlyWireProbe, MultiEndpointProxy


class ProxyTests(unittest.TestCase):
    def test_random_model_reproducible_global_burst_bound_not_periodic(self):
        sequences = []
        for _ in range(2):
            proxy = MultiEndpointProxy(('127.0.0.1', 9), client_endpoints=50,
                                      drop_rate=30, burst=3, impairment_seed=20261009,
                                      trace_routes=True)
            try:
                for number in range(10000):
                    proxy._incoming_route = ('127.0.0.1', 10000 + number % 50)
                    proxy._enqueue('to_server', b'fixture')
                decisions = [row['outcome'] == 'drop' for row in proxy.route_trace]
                sequences.append(decisions)
                self.assertTrue(2500 < sum(decisions) < 3500)
                consecutive = 0
                for lost in decisions:
                    consecutive = consecutive + 1 if lost else 0
                    self.assertLessEqual(consecutive, 3)
                self.assertNotEqual(decisions[:50], decisions[50:100])
                self.assertEqual(proxy.stats['capacity_drops'], 0)
            finally:
                proxy._front.close(); proxy._back.close()
        self.assertEqual(*sequences)

    def test_random_corruption_changes_header_window_and_exempts_vn(self):
        proxy = UdpProxy(('127.0.0.1', 9), corrupt_rate=100, burst=3)
        packet = b'\xc0\x00\x00\x00\x01' + bytes(100)
        vn = b'\xc0' + bytes(4) + b'version-negotiation'
        try:
            proxy._enqueue('to_client', packet)
            mutated = proxy._queue[-1][-1]
            changes = [i for i, (a, b) in enumerate(zip(packet, mutated)) if a != b]
            self.assertEqual(len(changes), 1)
            self.assertLessEqual(changes[0], 50)
            proxy._enqueue('to_client', vn)
            self.assertEqual(proxy._queue[-1][-1], vn)
            self.assertEqual(proxy.stats['to_client_corrupted'], 1)
            self.assertEqual(proxy._consecutive['to_client'], 0)
        finally:
            proxy._front.close(); proxy._back.close()

    def test_random_model_forces_forward_after_maximum_and_checks_settings(self):
        proxy = UdpProxy(('127.0.0.1', 9), drop_rate=100, burst=3)
        try:
            for _ in range(8): proxy._enqueue('to_server', b'fixture')
            self.assertEqual(proxy.stats['to_server_dropped'], 6)
            self.assertEqual(len(proxy._queue), 2)
        finally:
            proxy._front.close(); proxy._back.close()
        for options in ({'drop_rate':101}, {'drop_rate':30,'drop_every':10},
                        {'drop_rate':30,'corrupt_rate':30}):
            with self.assertRaises(ValueError): UdpProxy(('127.0.0.1',9), **options)

    def test_per_connection_loss_is_exactly_thirty_percent_and_at_most_three_consecutive(self):
        proxy = MultiEndpointProxy(('127.0.0.1', 9), client_endpoints=2,
                                  drop_every=10, burst=3, loss_scope='per-connection', trace_routes=True)
        try:
            for number in range(100):
                for port in (10001, 10002):
                    proxy._incoming_route = ('127.0.0.1', port)
                    proxy._enqueue('to_server', b'fixture')
            for port in (10001, 10002):
                rows=[r for r in proxy.route_trace if r['route']==('127.0.0.1',port)]
                self.assertEqual(len(rows),100)
                self.assertEqual(sum(r['outcome']=='drop' for r in rows),30)
                streak=maximum=0
                for r in rows:
                    streak=streak+1 if r['outcome']=='drop' else 0
                    maximum=max(maximum,streak)
                self.assertEqual(maximum,3)
                self.assertEqual([r['decision_number'] for r in rows],list(range(1,101)))
            self.assertEqual(proxy.stats['to_server_received'],200)
            self.assertEqual(proxy.stats['to_server_dropped'],60)
        finally:
            proxy._front.close();proxy._back.close()

    def test_delayed_send_to_closed_peer_is_rejected_not_forwarded(self):
        proxy = MultiEndpointProxy(('127.0.0.1', 9), client_endpoints=1)
        client = ('127.0.0.1', 10001)
        peer = Mock()
        peer.send.side_effect = ConnectionRefusedError()
        try:
            proxy._routes[client] = peer
            proxy._incoming_route = client
            proxy._enqueue('to_server', b'late close')
            proxy._flush()
            peer.send.assert_called_once_with(b'late close')
            self.assertEqual(proxy.stats['to_server_forwarded'], 0)
            self.assertEqual(proxy.stats['to_server_destination_unavailable'], 1)
            self.assertEqual(proxy._queued_bytes, 0)
            self.assertFalse(proxy._queue)
            self.assertFalse(proxy._destinations)
        finally:
            proxy._front.close()
            proxy._back.close()

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

    def test_multiconnect_keeps_old_return_path_and_delayed_destination(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second:
            server.bind(('127.0.0.1', 0))
            for sock in (server, first, second):
                sock.settimeout(1)
            with MultiEndpointProxy(server.getsockname(), client_endpoints=2, delay=0.01) as proxy:
                first.sendto(b'first', proxy.address)
                data, path1 = server.recvfrom(100)
                self.assertEqual(data, b'first')
                server.sendto(b'late-first', path1)
                second.sendto(b'second', proxy.address)
                data, path2 = server.recvfrom(100)
                self.assertEqual(data, b'second')
                self.assertNotEqual(path1, path2)
                server.sendto(b'second-reply', path2)
                self.assertEqual(first.recvfrom(100)[0], b'late-first')
                self.assertEqual(second.recvfrom(100)[0], b'second-reply')
                first.sendto(b'old-close', proxy.address)
                data, path = server.recvfrom(100)
                self.assertEqual((data, path), (b'old-close', path1))

    def test_resumption_endpoint_allowance_is_bounded_and_cannot_return_to_old_port(self):
        for maximum in (1, 2):
            proxy = UdpProxy(('127.0.0.1', 9), client_endpoints=maximum)
            try:
                self.assertTrue(proxy._accept_client(('127.0.0.1', 10001)))
                self.assertTrue(proxy._accept_client(('127.0.0.1', 10001)))
                self.assertFalse(proxy._accept_client(('192.0.2.1', 10002)))
                self.assertEqual(proxy._accept_client(('127.0.0.1', 10002)), maximum == 2)
                self.assertFalse(proxy._accept_client(('127.0.0.1', 10003)))
                if maximum == 2:
                    self.assertFalse(proxy._accept_client(('127.0.0.1', 10001)))
            finally:
                proxy._front.close()
                proxy._back.close()

    def test_fifty_sequential_endpoints_keep_old_and_foreign_ports_rejected(self):
        proxy = UdpProxy(('127.0.0.1', 9), client_endpoints=50)
        try:
            for index in range(50):
                self.assertTrue(proxy._accept_client(('127.0.0.1', 10000 + index)))
                if index:
                    self.assertFalse(proxy._accept_client(('127.0.0.1', 9999 + index)))
            self.assertFalse(proxy._accept_client(('127.0.0.1', 10050)))
            self.assertFalse(proxy._accept_client(('192.0.2.1', 10049)))
        finally:
            proxy._front.close()
            proxy._back.close()
        for invalid in (0, 65):
            with self.assertRaises(ValueError):
                UdpProxy(('127.0.0.1', 9), client_endpoints=invalid)

    def test_one_blackhole_drops_both_directions_then_recovers(self):
        proxy = UdpProxy(('127.0.0.1', 9), blackhole_after_bytes=4, blackhole_seconds=2.0)
        try:
            with patch('udp_impairment.time.monotonic', return_value=10.0):
                proxy._enqueue('to_server', b'1234')
            with patch('udp_impairment.time.monotonic', return_value=11.0):
                proxy._enqueue('to_client', b'reply')
            with patch('udp_impairment.time.monotonic', return_value=12.1):
                proxy._enqueue('to_server', b'after')
            self.assertEqual(proxy.stats['to_server_blackhole_dropped'], 1)
            self.assertEqual(proxy.stats['to_client_blackhole_dropped'], 1)
            self.assertEqual(proxy._blackhole_started, 10.0)
            self.assertEqual(len(proxy._queue), 1)
            self.assertEqual(proxy._queue[0][-1], b'after')
        finally:
            proxy._front.close()
            proxy._back.close()

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

    def test_greased_fixed_bit_preserves_packet_lengths(self):
        self.assertEqual(EarlyWireProbe.packet_lengths(b"\x03server01" + bytes(31)),
                         [('one_rtt', 40)])
        early = b"\x90\x00\x00\x00\x01\x00\x00\x04" + b"efgh"
        self.assertEqual(EarlyWireProbe.packet_lengths(early), [('zero_rtt', len(early))])

    def test_nonzero_unclassified_suffix_is_not_silently_ignored(self):
        initial = b"\xc0\x00\x00\x00\x01\x00\x00\x00\x04" + b"abcd"
        with self.assertRaises(ValueError):
            EarlyWireProbe.packet_lengths(initial + b"\x00\x01")


if __name__ == '__main__':
    unittest.main()
