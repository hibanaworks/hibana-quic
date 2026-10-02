#!/usr/bin/env python3
"""Read a compiler-emitted ARM layout table; never establish firmware fit."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

SYMBOL = b'HIBANA_QUIC_ASYNC_STORAGE_BUDGET'
MARKER = 0x48415331
FIXED_NAMES = [
    'transport_endpoint_state', 'legacy_hibana_session_kit', 'legacy_carrier',
    'legacy_runtime_slab', 'tls_caller_buffers', 'crypto_receive_data',
    'crypto_receive_bitmap', 'one_live_stream', 'two_send_chunks',
    'sixteen_send_references', 'six_legacy_role_program_handles',
    'three_1536_byte_udp_buffers', 'application_scratch', 'signing_key',
    'one_early_request', 'one_early_quarantine_stream', 'four_early_control_slots',
    'two_managed_paths', 'eight_local_cid_history', 'sixteen_peer_cid_history',
    'preferred_ee_prefix_buffer', 'initial_hibana_session_kit', 'initial_carrier',
    'initial_runtime_slab', 'four_initial_endpoint_handles',
    'four_initial_role_program_handles', 'four_initial_mailbox_headers',
    'four_initial_mailbox_slots', 'two_initial_exchanges', 'flat_task_set_3',
]
FUTURE_NAMES = [
    'initial_rx_service', 'initial_tx_service', 'initial_service_alignment',
    'owning_join2_initial_pair', 'handshake_receive', 'handshake_transmit',
    'handshake_adapter_result', 'transport_receive', 'transport_transmit',
    'transport_adapter_result',
]
DETAIL_NAMES = ['packet_key', 'packet_command', 'packet_reply', 'handshake_endpoint']
WORDS = 1 + len(FIXED_NAMES) + len(FUTURE_NAMES) + len(DETAIL_NAMES) + 1


def _unpack(fmt, data, offset):
    if offset < 0 or offset + struct.calcsize(fmt) > len(data):
        raise ValueError('truncated ELF structure')
    return struct.unpack_from(fmt, data, offset)


def _slice(data, offset, length):
    if offset < 0 or length < 0 or offset + length > len(data):
        raise ValueError('ELF region outside file')
    return data[offset:offset + length]


def read(path):
    data = Path(path).read_bytes()
    if data[:6] != b'\x7fELF\x01\x01':
        raise ValueError('expected little-endian ELF32')
    header = _unpack('<16sHHIIIIIHHHHHH', data, 0)
    if header[2] != 40:
        raise ValueError('expected ARM ELF')
    if header[11] != 40 or not header[12]:
        raise ValueError('unsupported ELF section table')
    sections = [_unpack('<10I', data, header[6] + i * 40)
                for i in range(header[12])]
    for section in sections:
        if section[1] != 2:
            continue
        if section[9] != 16 or section[5] % 16 or section[6] >= len(sections):
            raise ValueError('invalid ELF symbol table')
        strings = sections[section[6]]
        names = _slice(data, strings[4], strings[5])
        for offset in range(section[4], section[4] + section[5], 16):
            name, value, size, _, _, index = _unpack('<IIIBBH', data, offset)
            if name >= len(names):
                raise ValueError('invalid ELF symbol name')
            end = names.find(b'\0', name)
            if end < 0:
                raise ValueError('unterminated ELF symbol name')
            if names[name:end] != SYMBOL:
                continue
            if size != WORDS * 4:
                raise ValueError('unexpected metrics schema size')
            if not 0 < index < len(sections):
                raise ValueError('invalid metrics section')
            target = sections[index]
            relative = value - target[3]
            if relative < 0 or relative + size > target[5]:
                raise ValueError('metrics outside section')
            values = _unpack(f'<{WORDS}I', data, target[4] + relative)
            if values[0] != MARKER:
                raise ValueError('unexpected metrics schema marker')
            return summarize(values, hashlib.sha256(data).hexdigest())
    raise ValueError('target metrics symbol not found')


def summarize(values, digest):
    fields = dict(zip(FIXED_NAMES + FUTURE_NAMES + DETAIL_NAMES, values[1:-1], strict=True))
    fixed = {name: fields[name] for name in FIXED_NAMES}
    futures = {name: fields[name] for name in FUTURE_NAMES}
    details = {name: fields[name] for name in DETAIL_NAMES}
    # Independent pinned services share one borrowed TaskSet. Endpoint state,
    # the arena, mailbox slots and buffers are distinct caller-owned objects.
    pinned = futures['initial_rx_service'] + futures['initial_tx_service']
    largest_io = max(futures[name] for name in (
        'transport_receive', 'transport_transmit', 'transport_adapter_result'))
    subtotal = sum(fixed.values()) + pinned + largest_io
    return {
        'schema_version': 1,
        'target': 'thumbv6m-none-eabi',
        'elf_sha256': digest,
        'status': 'LAYOUT_ONLY_NOT_FIRMWARE_FIT',
        'fixed_caller_storage_bytes': fixed,
        'future_layout_bytes': futures,
        'informational_type_layout_bytes_not_added_again': details,
        'flat_pinned_initial_pair_bytes': pinned,
        'largest_borrowed_transport_io_future_bytes': largest_io,
        'selected_flat_composition_bytes': subtotal,
        'reference_rp2040_sram_bytes': values[-1],
        'reference_bytes_before_all_unmeasured_costs': values[-1] - subtotal,
        'profile': (
            'Partial async Initial protection plus legacy Driver and bounded TLS; '
            'one stream, two 1024-byte chunks, 16KiB TLS buffers, 8/16/8KiB CRYPTO '
            'windows, 1536-byte actor packets, one-slot command/reply mailboxes, '
            'two separately pinned key services, separate 32KiB Initial runtime '
            'slab, largest one-at-a-time borrowed transport I/O future. Optional '
            'early/path/CID capacities include both client and server buffers. '
            'The sum is a selected composition, not an actual application root.'),
        'unmeasured': [
            'application_root_coroutine_and_extra_owning_join_layers',
            'future_construction_moves_and_peak_synchronous_crypto_stack',
            'alignment_padding_between_separate_caller_objects',
            'network_stack_driver_executor_and_board_runtime',
            'interrupt_stack', 'trust_anchors_certificates_and_entropy_provider',
            'resumption_ticket_cache_and_replay_storage',
            'optional_trace_output_buffer_and_sink', 'hardware_execution',
        ],
        'notes': [
            'Opaque futures are measured by compile-time function-item output '
            'type inference; no future is constructed, polled or allocated.',
            'Owning join2 is an alternative aggregate, not added to its children. '
            'Nested owning joins and actual application owners can be much larger.',
            'Future layout is compiler, target and profile dependent. '
            'This cannot establish a complete Pico RAM, stack, flash or timing budget.',
        ],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf')
    args = parser.parse_args()
    print(json.dumps(read(args.elf), indent=2))
