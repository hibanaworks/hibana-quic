#!/usr/bin/env python3
"""Read historical legacy-controller layout metrics, not the current connection."""
import argparse, hashlib, json, struct
from pathlib import Path

NAMES = [
    'transport_endpoint_state','hibana_session_kit','bounded_carrier','runtime_slab',
    'tls_caller_buffers','crypto_receive_data','crypto_receive_bitmap','one_live_stream',
    'two_send_chunks','sixteen_send_references','six_role_program_handles',
    'three_udp_mtu_buffers','application_scratch','signing_key',
]

EXTENDED_NAMES = [
    'one_early_request', 'one_early_quarantine_stream', 'four_early_control_slots',
    'two_managed_paths', 'eight_local_cid_history', 'sixteen_peer_cid_history',
    'preferred_ee_prefix_buffer',
]

def read(path):
    data=Path(path).read_bytes()
    if data[:6] != b'\x7fELF\x01\x01': raise ValueError('expected little-endian ELF32 target image')
    hdr=struct.unpack_from('<16sHHIIIIIHHHHHH',data)
    sections=[struct.unpack_from('<10I',data,hdr[6]+i*hdr[11]) for i in range(hdr[12])]
    for sec in sections:
        if sec[1] != 2: continue
        strings=sections[sec[6]]; names=data[strings[4]:strings[4]+strings[5]]
        for offset in range(sec[4],sec[4]+sec[5],sec[9]):
            name,value,size,_,_,section=struct.unpack_from('<IIIBBH',data,offset)
            if names[name:names.find(b'\0',name)] != b'HIBANA_QUIC_TARGET_BUDGET': continue
            target=sections[section]; start=target[4]+value-target[3]
            if size not in (64, 92): raise ValueError('unexpected metrics schema size')
            values=struct.unpack_from(f'<{size // 4}I',data,start)
            schema = {0x48425131: (1, NAMES), 0x48425132: (2, NAMES + EXTENDED_NAMES)}.get(values[0])
            if schema is None: raise ValueError('unexpected metrics schema marker')
            version, names = schema
            fields=dict(zip(names,values[1:-1],strict=True)); total=sum(fields.values())
            return {'schema_version':version,'target':'thumbv6m-none-eabi','elf_sha256':hashlib.sha256(data).hexdigest(),
                    'measured_layout_and_selected_storage_bytes':fields,'subtotal_bytes':total,
                    'reference_rp2040_sram_bytes':values[-1],'unallocated_reference_bytes':values[-1]-total,
                    'status':'LAYOUT_ONLY_NOT_FIRMWARE_FIT',
                    'architecture':'removed_legacy_controller',
                    'current_connection_budget':'UNAVAILABLE_NOT_MEASURED',
                    'unmeasured':['peak_stack_and_temporaries','network_stack_and_driver','IRQ_stack','board_specific_runtime','hardware_execution','resumption_ticket_cache_and_replay_storage','trust_anchor_storage_and_entropy_provider','optional_trace_output_buffer_and_sink'],
                    'profile':'one live stream, two 1024-byte send chunks, 16KiB TLS buffers, 8KiB Initial/application and 16KiB Handshake CRYPTO windows; v2 also selects one early request, one quarantine stream, four early control slots, two managed paths, CID histories and a 2KiB preferred-EE prefix; this intentionally includes both client and server early buffers; caller capacity choices are not measurements of actual board use'}
    raise ValueError('target metrics symbol not found')

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('elf');args=p.parse_args()
    print(json.dumps(read(args.elf),indent=2))
