//! Historical ARM tables only. These are never a current firmware-fit result.
use super::{Result, require};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const TARGET: &[&str] = &[
    "transport_endpoint_state",
    "hibana_session_kit",
    "bounded_carrier",
    "runtime_slab",
    "tls_caller_buffers",
    "crypto_receive_data",
    "crypto_receive_bitmap",
    "one_live_stream",
    "two_send_chunks",
    "sixteen_send_references",
    "six_role_program_handles",
    "three_udp_mtu_buffers",
    "application_scratch",
    "signing_key",
];
const EXTENDED: &[&str] = &[
    "one_early_request",
    "one_early_quarantine_stream",
    "four_early_control_slots",
    "two_managed_paths",
    "eight_local_cid_history",
    "sixteen_peer_cid_history",
    "preferred_ee_prefix_buffer",
];
const FIXED: &[&str] = &[
    "transport_endpoint_state",
    "legacy_hibana_session_kit",
    "legacy_carrier",
    "legacy_runtime_slab",
    "tls_caller_buffers",
    "crypto_receive_data",
    "crypto_receive_bitmap",
    "one_live_stream",
    "two_send_chunks",
    "sixteen_send_references",
    "six_legacy_role_program_handles",
    "three_1536_byte_udp_buffers",
    "application_scratch",
    "signing_key",
    "one_early_request",
    "one_early_quarantine_stream",
    "four_early_control_slots",
    "two_managed_paths",
    "eight_local_cid_history",
    "sixteen_peer_cid_history",
    "preferred_ee_prefix_buffer",
    "initial_hibana_session_kit",
    "initial_carrier",
    "initial_runtime_slab",
    "four_initial_endpoint_handles",
    "four_initial_role_program_handles",
    "four_initial_mailbox_headers",
    "four_initial_mailbox_slots",
    "two_initial_exchanges",
    "flat_task_set_3",
];
const FUTURES: &[&str] = &[
    "initial_rx_service",
    "initial_tx_service",
    "initial_service_alignment",
    "owning_join2_initial_pair",
    "handshake_receive",
    "handshake_transmit",
    "handshake_adapter_result",
    "transport_receive",
    "transport_transmit",
    "transport_adapter_result",
];
const DETAILS: &[&str] = &[
    "packet_key",
    "packet_command",
    "packet_reply",
    "handshake_endpoint",
];

fn region(data: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    let end = offset.checked_add(len).ok_or("ELF offset overflow")?;
    data.get(offset..end)
        .ok_or_else(|| "ELF region outside file".into())
}
fn u16_at(data: &[u8], offset: usize) -> Result<usize> {
    Ok(u16::from_le_bytes(region(data, offset, 2)?.try_into()?) as usize)
}
fn u32_at(data: &[u8], offset: usize) -> Result<usize> {
    Ok(u32::from_le_bytes(region(data, offset, 4)?.try_into()?) as usize)
}
fn symbol<'a>(data: &'a [u8], wanted: &[u8]) -> Result<&'a [u8]> {
    require(
        region(data, 0, 6)? == b"\x7fELF\x01\x01" && u16_at(data, 18)? == 40,
        "expected little-endian ARM ELF32",
    )?;
    let count = u16_at(data, 48)?;
    require(
        u16_at(data, 46)? == 40 && count > 0,
        "invalid section table",
    )?;
    let table = region(data, u32_at(data, 32)?, count * 40)?;
    let sections: Vec<_> = table.chunks_exact(40).collect();
    for section in &sections {
        if u32_at(section, 4)? != 2 {
            continue;
        }
        let size = u32_at(section, 20)?;
        require(
            u32_at(section, 36)? == 16 && size % 16 == 0,
            "invalid symbol table",
        )?;
        let strings = sections
            .get(u32_at(section, 24)?)
            .ok_or("invalid string section")?;
        let names = region(data, u32_at(strings, 16)?, u32_at(strings, 20)?)?;
        let entries = region(data, u32_at(section, 16)?, size)?;
        for entry in entries.chunks_exact(16) {
            let tail = names
                .get(u32_at(entry, 0)?..)
                .ok_or("invalid symbol name")?;
            let end = tail
                .iter()
                .position(|b| *b == 0)
                .ok_or("unterminated symbol name")?;
            if &tail[..end] != wanted {
                continue;
            }
            let index = u16_at(entry, 14)?;
            require(index > 0, "undefined metrics symbol")?;
            let target = sections.get(index).ok_or("invalid metrics section")?;
            let relative = u32_at(entry, 4)?
                .checked_sub(u32_at(target, 12)?)
                .ok_or("metrics precede section")?;
            let contents = region(data, u32_at(target, 16)?, u32_at(target, 20)?)?;
            return region(contents, relative, u32_at(entry, 8)?);
        }
    }
    Err("metrics symbol not found".into())
}
fn fields(names: &[&str], words: &[u32]) -> Result<BTreeMap<String, u64>> {
    require(names.len() == words.len(), "unexpected metrics schema size")?;
    Ok(names
        .iter()
        .zip(words)
        .map(|(n, v)| ((*n).to_owned(), u64::from(*v)))
        .collect())
}

pub(super) fn read(data: &[u8], symbol_name: &str) -> Result<serde_json::Value> {
    let bytes = symbol(data, symbol_name.as_bytes())?;
    require(
        bytes.len() % 4 == 0 && bytes.len() >= 8,
        "unexpected metrics schema size",
    )?;
    let values: Vec<_> = bytes
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();
    let mut result = json!({
        "target":"thumbv6m-none-eabi", "elf_sha256":format!("{:x}",Sha256::digest(data)),
        "status":"LAYOUT_ONLY_NOT_FIRMWARE_FIT", "architecture":"removed_legacy_controller",
        "current_connection_budget":"UNAVAILABLE_NOT_MEASURED",
        "reference_rp2040_sram_bytes":values[values.len()-1],
        "unmeasured":["application_root_coroutine_and_extra_owning_join_layers", "peak_stack_and_temporaries",
            "network_stack_driver_executor_and_board_runtime", "interrupt_stack",
            "trust_anchors_certificates_and_entropy_provider", "resumption_ticket_cache_and_replay_storage",
            "optional_trace_output_buffer_and_sink", "hardware_execution"],
    });
    let reference = i64::from(values[values.len() - 1]);
    if symbol_name == "HIBANA_QUIC_TARGET_BUDGET" {
        let names = match values[0] {
            0x48425131 => TARGET.to_vec(),
            0x48425132 => [TARGET, EXTENDED].concat(),
            _ => return Err("unexpected target schema marker".into()),
        };
        let measured = fields(&names, &values[1..values.len() - 1])?;
        let total: u64 = measured.values().sum();
        result["schema_version"] = json!(values[0] - 0x48425130);
        result["measured_layout_and_selected_storage_bytes"] = json!(measured);
        result["subtotal_bytes"] = json!(total);
        result["unallocated_reference_bytes"] = json!(reference - total as i64);
    } else {
        require(
            symbol_name == "HIBANA_QUIC_ASYNC_STORAGE_BUDGET" && values[0] == 0x48415331,
            "unexpected async schema marker",
        )?;
        require(
            values.len() == 2 + FIXED.len() + FUTURES.len() + DETAILS.len(),
            "unexpected metrics schema size",
        )?;
        let fixed_end = 1 + FIXED.len();
        let future_end = fixed_end + FUTURES.len();
        let fixed = fields(FIXED, &values[1..fixed_end])?;
        let futures = fields(FUTURES, &values[fixed_end..future_end])?;
        let details = fields(DETAILS, &values[future_end..values.len() - 1])?;
        let pinned = futures["initial_rx_service"] + futures["initial_tx_service"];
        let largest = [
            "transport_receive",
            "transport_transmit",
            "transport_adapter_result",
        ]
        .iter()
        .map(|n| futures[*n])
        .max()
        .unwrap();
        let subtotal = fixed.values().sum::<u64>() + pinned + largest;
        result["schema_version"] = json!(1);
        result["fixed_caller_storage_bytes"] = json!(fixed);
        result["future_layout_bytes"] = json!(futures);
        result["informational_type_layout_bytes_not_added_again"] = json!(details);
        result["flat_pinned_initial_pair_bytes"] = json!(pinned);
        result["largest_borrowed_transport_io_future_bytes"] = json!(largest);
        result["selected_flat_composition_bytes"] = json!(subtotal);
        result["reference_bytes_before_all_unmeasured_costs"] = json!(reference - subtotal as i64);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(name: &str, marker: u32, words: usize) -> Vec<u8> {
        let mut data = vec![0; 212];
        data[..6].copy_from_slice(b"\x7fELF\x01\x01");
        for (offset, value) in [(18, 40u16), (46, 40), (48, 4)] {
            data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        data[32..36].copy_from_slice(&52u32.to_le_bytes());
        let mut put = |offset: usize, value: usize| {
            data[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes())
        };
        for (index, values) in [
            (1, [0, 1, 0, 0x2000, 212, words * 4, 0, 0, 4, 0]),
            (2, [0, 3, 0, 0, 212 + words * 4, name.len() + 2, 0, 0, 1, 0]),
            (
                3,
                [
                    0,
                    2,
                    0,
                    0,
                    212 + words * 4 + name.len() + 2,
                    16,
                    2,
                    0,
                    4,
                    16,
                ],
            ),
        ] {
            for (i, value) in values.into_iter().enumerate() {
                put(52 + index * 40 + i * 4, value);
            }
        }
        data.extend(marker.to_le_bytes());
        for _ in 0..words - 2 {
            data.extend(100u32.to_le_bytes());
        }
        data.extend(270336u32.to_le_bytes());
        data.push(0);
        data.extend(name.as_bytes());
        data.push(0);
        for value in [1u32, 0x2000, (words * 4) as u32] {
            data.extend(value.to_le_bytes());
        }
        data.extend([0, 0, 1, 0]);
        data
    }
    #[test]
    fn historical_tables_preserve_disjoint_accounting_and_no_fit_claim() {
        let name = "HIBANA_QUIC_TARGET_BUDGET";
        for (marker, count) in [
            (0x48425131, TARGET.len() + 2),
            (0x48425132, TARGET.len() + EXTENDED.len() + 2),
        ] {
            let value = read(&fixture(name, marker, count), name).unwrap();
            assert_eq!(value["subtotal_bytes"], ((count - 2) * 100) as u64);
            assert_eq!(
                value["current_connection_budget"],
                "UNAVAILABLE_NOT_MEASURED"
            );
        }
        let name = "HIBANA_QUIC_ASYNC_STORAGE_BUDGET";
        let value = read(
            &fixture(
                name,
                0x48415331,
                2 + FIXED.len() + FUTURES.len() + DETAILS.len(),
            ),
            name,
        )
        .unwrap();
        assert_eq!(value["flat_pinned_initial_pair_bytes"], 200);
        assert_eq!(
            value["selected_flat_composition_bytes"],
            ((FIXED.len() + 3) * 100) as u64
        );
        assert_eq!(value["status"], "LAYOUT_ONLY_NOT_FIRMWARE_FIT");
        let mut large = fixture(
            name,
            0x48415331,
            2 + FIXED.len() + FUTURES.len() + DETAILS.len(),
        );
        for offset in (216..212 + (FIXED.len() + FUTURES.len() + DETAILS.len() + 1) * 4).step_by(4)
        {
            large[offset..offset + 4].copy_from_slice(&100000u32.to_le_bytes());
        }
        let value = read(&large, name).unwrap();
        assert!(
            value["reference_bytes_before_all_unmeasured_costs"]
                .as_i64()
                .unwrap()
                < 0
        );
        assert_eq!(value["status"], "LAYOUT_ONLY_NOT_FIRMWARE_FIT");
    }
    #[test]
    fn malformed_elf_and_oversized_schema_fail_closed() {
        let name = "HIBANA_QUIC_ASYNC_STORAGE_BUDGET";
        let valid = fixture(
            name,
            0x48415331,
            2 + FIXED.len() + FUTURES.len() + DETAILS.len(),
        );
        for length in 0..valid.len() {
            assert!(read(&valid[..length], name).is_err());
        }
        for offset in [18, 32, 46, 48, 212, valid.len() - 8] {
            let mut bad = valid.clone();
            bad[offset..offset + 2].copy_from_slice(&[0xff, 0xff]);
            assert!(read(&bad, name).is_err());
        }
    }
}
