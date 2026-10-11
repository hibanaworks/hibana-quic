//! Bounded handshake packet storage, authentication and CRYPTO reassembly.
//! This module neither polls I/O nor advances a Hibana endpoint.
use crate::crypto::{self, IntegrityBudget};
use crate::quic::imp::kernel::packet::{
    self, Frame, FrameIter, Header, LongType, PacketIter, ParseLimits,
};
use crate::quic::imp::{crypto_buffer::CryptoBuffer, initial, recovery};
use crate::quic::{Clock, Config, ConnectionId, Error, ReceivedDatagram, Side, Storage};
use hibana_tls::handshake::keys::ReceivePacketKey;
use hibana_tls::quic::Level;

pub(in crate::quic) struct HandshakePackets<'keys, 'scope, 'buf, const N: usize> {
    pub(in crate::quic) initial: &'keys initial::Keys<'scope>,
    pub(in crate::quic) handshake: Option<ReceivePacketKey<'scope>>,
    pub(in crate::quic) integrity: IntegrityBudget,
    pub(in crate::quic) reassembly: [CryptoBuffer<'buf>; 2],
    pub(in crate::quic) largest: [Option<u64>; 2],
    pub(in crate::quic) datagram: [u8; N],
    pub(in crate::quic) len: usize,
    pub(in crate::quic) received_at: u64,
    pub(in crate::quic) ecn: Option<crate::io::Codepoint>,
    pub(in crate::quic) path: Option<crate::io::Address>,
    pub(in crate::quic) offset: usize,
    pub(in crate::quic) opened: [u8; N],
    // One owned ciphertext packet, not a TLS/protocol phase flag. It cannot
    // produce ACK or CRYPTO effects until the real Handshake key arrives.
    pub(in crate::quic) pending_handshake: Option<([u8; N], ReceivedDatagram, u64)>,
}
impl<'scope, const N: usize> HandshakePackets<'_, 'scope, '_, N> {
    pub(in crate::quic) fn apply<const P: usize>(
        &mut self,
        slots: &Storage<'scope, '_, N, P>,
        config: Config<'_>,
        book: &mut recovery::Rx<'_, 'scope, N>,
        clock: &impl Clock,
    ) -> Result<(), Error> {
        let untrusted = match PacketIter::new(
            &self.datagram[self.offset..self.len],
            config.local_connection_id.len(),
            1,
        )?
        .next()
        {
            Some(Ok(packet)) => packet,
            _ => {
                self.offset = self.len;
                return Ok(());
            }
        };
        self.offset += untrusted.bytes.len();
        let (level, index, pn_offset, source_id, wire_version) = match untrusted.header {
            Header::Long {
                version,
                kind,
                destination_id,
                source_id,
                packet_number_offset,
                ..
            } => {
                if version != config.version
                    && !(kind == LongType::Initial
                        && version == crate::quic::imp::kernel::version::Version::V1)
                {
                    return Ok(());
                }
                if destination_id != config.local_connection_id
                    && !(config.side == Side::Server
                        && matches!(kind, LongType::Initial | LongType::ZeroRtt)
                        && destination_id
                            == config
                                .retry_source_id
                                .unwrap_or(config.original_destination_id))
                {
                    return Ok(());
                }
                match kind {
                    LongType::Initial if config.side != Side::Server || self.len >= 1200 => {
                        (Level::Initial, 0, packet_number_offset, source_id, version)
                    }
                    LongType::Handshake => (
                        Level::Handshake,
                        1,
                        packet_number_offset,
                        source_id,
                        version,
                    ),
                    LongType::ZeroRtt if config.side == Side::Server => {
                        if source_id == slots.peer.borrow().bytes()
                            && let Some(pending) = slots.early_packets.borrow_mut().as_mut()
                        {
                            pending.retain_packet(untrusted.bytes, self.ecn);
                        }
                        return Ok(());
                    }
                    _ => return Ok(()),
                }
            }
            Header::Short { destination_id, .. } => {
                if destination_id == config.local_connection_id {
                    slots.retain_application(
                        untrusted.bytes,
                        self.ecn,
                        self.path,
                        self.received_at,
                    )?;
                }
                return Ok(());
            }
            _ => return Ok(()),
        };
        // Both Initial key access and AEAD end before the retirement edge can await.
        let (authentication, header_len, pn) = {
            let initial_key = self.initial.read_version(wire_version);
            let key = if index == 0 {
                match initial_key.as_ref() {
                    Some(key) => key,
                    None => return Ok(()),
                }
            } else {
                match self.handshake.as_ref() {
                    Some(key) => key,
                    None => {
                        // A reordered server flight can precede ServerHello.
                        // Retain one bounded packet while continuing to read
                        // Initial input; never block the key-producing input.
                        if self.pending_handshake.is_none() {
                            let mut bytes = [0; N];
                            bytes[..untrusted.bytes.len()].copy_from_slice(untrusted.bytes);
                            self.pending_handshake = Some((
                                bytes,
                                ReceivedDatagram {
                                    len: untrusted.bytes.len(),
                                    ecn: self.ecn,
                                    path: self.path,
                                },
                                self.received_at,
                            ));
                        }
                        return Ok(());
                    }
                }
            };
            self.opened[..untrusted.bytes.len()].copy_from_slice(untrusted.bytes);
            let bytes = &mut self.opened[..untrusted.bytes.len()];
            let pn_len = match key.unprotect_header(bytes, pn_offset) {
                Ok(len) => len,
                Err(_) => return Ok(()),
            };
            let (truncated, _) =
                packet::decode_truncated_packet_number(bytes[0], &bytes[pn_offset..])?;
            let pn = packet::restore_packet_number(truncated, pn_len as u8, self.largest[index])?;
            let (header, payload) = bytes.split_at_mut(pn_offset + pn_len);
            let authentication =
                match key.open_authenticated(pn, header, payload, &mut self.integrity) {
                    Ok(receipt) => receipt,
                    Err(crypto::Error::AuthenticationFailed) => return Ok(()),
                    Err(error) => return Err(error.into()),
                };
            packet::validate_reserved_bits(header[0])?;
            (authentication, pn_offset + pn_len, pn)
        };
        let plaintext = &self.opened[header_len..header_len + authentication.len()];
        if self.largest.iter().any(Option::is_some) || config.side == Side::Server {
            if slots.peer.borrow().bytes() != source_id {
                return Err(Error::Binding);
            }
        } else {
            *slots.peer.borrow_mut() = ConnectionId::new(source_id)?;
        }
        self.largest[index] = Some(self.largest[index].map_or(pn, |last| last.max(pn)));
        let outcome = book.apply_packet(
            authentication,
            plaintext,
            self.received_at,
            clock.now(),
            self.ecn,
        )?;
        slots.schedule.changed()?;
        if !outcome.duplicate {
            for frame in FrameIter::new(
                plaintext,
                if level == Level::Initial {
                    packet::EncryptionLevel::Initial
                } else {
                    packet::EncryptionLevel::Handshake
                },
                ParseLimits::default(),
            )? {
                match frame? {
                    Frame::Crypto { offset, data } => {
                        self.reassembly[index].insert(offset, data)?
                    }
                    Frame::Padding { .. } | Frame::Ping | Frame::Ack { .. } => {}
                    _ => return Err(Error::UnsupportedFrame),
                }
            }
        }
        Ok(())
    }
}
