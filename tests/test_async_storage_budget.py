"""Test layout framing and accounting without needing a target toolchain."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    'async_budget', Path(__file__).parents[1] / 'tools/dev/read_async_storage_budget.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def fixture():
    values = [reader.MARKER] + [100] * (reader.WORDS - 2) + [270336]
    payload = struct.pack(f'<{len(values)}I', *values)
    strings = b'\0' + reader.SYMBOL + b'\0'
    header = struct.pack('<16sHHIIIIIHHHHHH', b'\x7fELF\x01\x01' + bytes(10),
                         2, 40, 1, 0, 0, 52, 0, 52, 0, 0, 40, 4, 0)
    start = 52 + 4 * 40
    sections = [bytes(40),
                struct.pack('<10I', 0, 1, 0, 0x2000, start, len(payload), 0, 0, 4, 0),
                struct.pack('<10I', 0, 3, 0, 0, start + len(payload), len(strings), 0, 0, 1, 0),
                struct.pack('<10I', 0, 2, 0, 0, start + len(payload) + len(strings), 16, 2, 0, 4, 16)]
    symbol = struct.pack('<IIIBBH', 1, 0x2000, len(payload), 0, 0, 1)
    return header + b''.join(sections) + payload + strings + symbol


class AsyncStorageBudget(unittest.TestCase):
    def read(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'table.elf'
            path.write_bytes(data)
            return reader.read(path)

    def test_disjoint_sum_excludes_informational_and_alternative_futures(self):
        result = self.read(fixture())
        self.assertEqual(result['selected_flat_composition_bytes'],
                         (len(reader.FIXED_NAMES) + 2 + 1) * 100)
        self.assertEqual(result['flat_pinned_initial_pair_bytes'], 200)
        self.assertEqual(result['status'], 'LAYOUT_ONLY_NOT_FIRMWARE_FIT')
        self.assertEqual(result['architecture'], 'removed_legacy_controller')
        self.assertEqual(result['current_connection_budget'], 'UNAVAILABLE_NOT_MEASURED')
        self.assertIn('application_root_coroutine_and_extra_owning_join_layers',
                      result['unmeasured'])

    def test_bad_marker(self):
        data = bytearray(fixture())
        data[212:216] = bytes(4)
        with self.assertRaisesRegex(ValueError, 'marker'):
            self.read(data)

    def test_truncated(self):
        with self.assertRaises(ValueError):
            self.read(fixture()[:-1])

    def test_non_arm(self):
        data = bytearray(fixture())
        data[18:20] = struct.pack('<H', 3)
        with self.assertRaisesRegex(ValueError, 'ARM'):
            self.read(data)

    def test_oversized_schema(self):
        data = bytearray(fixture())
        data[-8:-4] = struct.pack('<I', reader.WORDS * 4 + 4)
        with self.assertRaisesRegex(ValueError, 'schema size'):
            self.read(data)

    def test_no_fit_claim_even_with_negative_remaining(self):
        values = [reader.MARKER] + [100000] * (reader.WORDS - 2) + [270336]
        result = reader.summarize(values, 'synthetic')
        self.assertLess(result['reference_bytes_before_all_unmeasured_costs'], 0)
        self.assertEqual(result['status'], 'LAYOUT_ONLY_NOT_FIRMWARE_FIT')
