"""Synthetic ELF framing tests; no firmware-fit claim."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    'target_budget', Path(__file__).parents[1] / 'scripts/read_target_budget.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def fixture(version):
    names = reader.NAMES + (reader.EXTENDED_NAMES if version == 2 else [])
    values = [0x48425130 + version] + [100] * len(names) + [270336]
    payload = struct.pack(f'<{len(values)}I', *values)
    strings = b'\0HIBANA_QUIC_TARGET_BUDGET\0'
    header = struct.pack('<16sHHIIIIIHHHHHH', b'\x7fELF\x01\x01' + bytes(10),
                         2, 40, 1, 0, 0, 52, 0, 52, 0, 0, 40, 4, 0)
    start = 52 + 4 * 40
    sections = [bytes(40),
                struct.pack('<10I', 0, 1, 0, 0x2000, start, len(payload), 0, 0, 4, 0),
                struct.pack('<10I', 0, 3, 0, 0, start + len(payload), len(strings), 0, 0, 1, 0),
                struct.pack('<10I', 0, 2, 0, 0, start + len(payload) + len(strings), 16, 2, 0, 4, 16)]
    symbol = struct.pack('<IIIBBH', 1, 0x2000, len(payload), 0, 0, 1)
    return header + b''.join(sections) + payload + strings + symbol


class TargetBudget(unittest.TestCase):
    def read(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'table.elf'
            path.write_bytes(data)
            return reader.read(path)

    def test_historical_v1(self):
        result = self.read(fixture(1))
        self.assertEqual(result['schema_version'], 1)
        self.assertEqual(result['subtotal_bytes'], len(reader.NAMES) * 100)
        self.assertEqual(result['status'], 'LAYOUT_ONLY_NOT_FIRMWARE_FIT')
        self.assertEqual(result['architecture'], 'removed_legacy_controller')
        self.assertEqual(result['current_connection_budget'], 'UNAVAILABLE_NOT_MEASURED')

    def test_extended_v2(self):
        result = self.read(fixture(2))
        self.assertEqual(result['schema_version'], 2)
        self.assertEqual(result['subtotal_bytes'], (len(reader.NAMES) + 7) * 100)
        self.assertEqual(result['measured_layout_and_selected_storage_bytes']['preferred_ee_prefix_buffer'], 100)
        self.assertEqual(result['unallocated_reference_bytes'], 270336 - result['subtotal_bytes'])

    def test_bad_marker_rejected(self):
        data = bytearray(fixture(2))
        data[212:216] = bytes(4)
        with self.assertRaisesRegex(ValueError, 'marker'):
            self.read(data)
