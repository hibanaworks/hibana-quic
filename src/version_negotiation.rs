//! Bounded QUIC v1 Version Negotiation policy, RFC 9000 sections 5.2, 6 and 17.2.1.
//!
//! Version Negotiation (VN) has no integrity protection and never authenticates
//! a server or a version choice. The v1-only client can abandon an incompatible
//! attempt; it cannot switch versions or restart TLS. A future multi-version
//! implementation needs authenticated version information and downgrade checks
//! from RFC 9368, rather than extending the version list in this module alone.
//!
//! Listener callers first route existing connections and retired CID tombstones.
//! Invoke `Listener::on_datagram` once per complete, untruncated, unmatched UDP
//! datagram, then send its one response at most once to that datagram's source.
//! A rejected local submission is not retried without another received datagram.
//! The response quota is burned on preparation and is not refunded. Responses
//! are at most 521 bytes, whereas admission requires at least 1200 received
//! bytes. This bounds reflection volume without treating a source address as
//! validated. Hosts still own source filtering, ingress limits and UDP metadata.
//!
//! For unknown versions, only version-invariant fields are interpreted. In
//! particular, CID lengths up to 255 are legal and v1 packet type/fixed-bit/CID
//! length rules do not apply. The output advertises exactly QUIC v1. Header
//! low bits come from an injected CryptoRng; the v1 multiplexing recommendation
//! to set bit 0x40 is followed. Receivers ignore all seven unused bits.
//!
//! Client callers open the VN window only after actual acceptance of an Initial
//! send. Every successfully processed peer packet, including an integrity-checked
//! Retry, closes that window. Invalid packets never close or reopen it. Both CIDs
//! are checked against the original flight. A valid VN omitting v1 abandons the
//! attempt silently; an on-path attacker can forge this denial of service, as
//! VN is unprotected. No key, PN, TLS, Retry, stream or peer-address state is
//! granted by any result in this module.
//!
//! Sources: <https://www.rfc-editor.org/rfc/rfc9000.html#section-6>,
//! <https://www.rfc-editor.org/rfc/rfc8999.html#section-6>,
//! <https://www.rfc-editor.org/rfc/rfc9368.html#section-4>.

use crate::packet::{Header, PacketIter, QUIC_V1};
use rand_core::{CryptoRng, RngCore};

pub const MIN_TRIGGER_DATAGRAM_BYTES: usize = 1200;
/// Ordinary IPv6 UDP payload maximum; jumbo datagrams are outside this profile.
pub const MAX_DATAGRAM_BYTES: usize = 65_527;
/// Header + two maximum invariant CIDs + the one supported version.
pub const MAX_RESPONSE_BYTES: usize = 7 + 255 + 255 + 4;
const _: () = assert!(MAX_RESPONSE_BYTES < MIN_TRIGGER_DATAGRAM_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfiguration,
    InvalidConnectionId,
    Capacity,
    Entropy,
    TimeWentBackwards,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscardReason {
    TooSmall,
    TooLarge,
    Malformed,
    ShortHeader,
    SupportedVersion,
    VersionNegotiation,
    RateLimited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerAction {
    Discard(DiscardReason),
    /// Only out[..len] is initialized. Submit once to this datagram's source.
    Send {
        len: usize,
    },
}

/// Listener-wide fixed-window response budget, independent of peer addresses.
/// A window permits at most the configured number of prepared responses. Two
/// adjacent windows can each use their full budget near their shared boundary.
#[derive(Debug)]
pub struct Listener {
    max_datagram_bytes: usize,
    max_responses: u32,
    window_us: u64,
    last_now: Option<u64>,
    window_start: u64,
    prepared: u32,
}

impl Listener {
    pub fn new(
        max_datagram_bytes: usize,
        max_responses_per_window: u32,
        window_us: u64,
    ) -> Result<Self, Error> {
        if !(MIN_TRIGGER_DATAGRAM_BYTES..=MAX_DATAGRAM_BYTES).contains(&max_datagram_bytes)
            || max_responses_per_window == 0
            || window_us == 0
        {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            max_datagram_bytes,
            max_responses: max_responses_per_window,
            window_us,
            last_now: None,
            window_start: 0,
            prepared: 0,
        })
    }

    /// No allocation or I/O. Ordinary v1 input is returned as a discard reason
    /// for this VN service; the host can continue its existing v1/Retry admission.
    /// Errors do not write output. Entropy failure never substitutes fixed bits.
    pub fn on_datagram<R: RngCore + CryptoRng>(
        &mut self,
        now_us: u64,
        datagram: &[u8],
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<ListenerAction, Error> {
        if self.last_now.is_some_and(|previous| now_us < previous) {
            return Err(Error::TimeWentBackwards);
        }
        let (window_start, prepared) =
            if self.last_now.is_none() || now_us - self.window_start >= self.window_us {
                (now_us, 0)
            } else {
                (self.window_start, self.prepared)
            };
        // Observing an ingress event advances time, but does not consume a
        // response. Invalid input cannot refill a window early.
        self.last_now = Some(now_us);
        self.window_start = window_start;
        self.prepared = prepared;
        if datagram.len() < MIN_TRIGGER_DATAGRAM_BYTES {
            return Ok(ListenerAction::Discard(DiscardReason::TooSmall));
        }
        if datagram.len() > self.max_datagram_bytes {
            return Ok(ListenerAction::Discard(DiscardReason::TooLarge));
        }
        if datagram[0] & 0x80 == 0 {
            return Ok(ListenerAction::Discard(DiscardReason::ShortHeader));
        }
        let parsed = PacketIter::new(datagram, 0, 1)
            .ok()
            .and_then(|mut packets| packets.next())
            .and_then(Result::ok);
        let Some(packet) = parsed else {
            return Ok(ListenerAction::Discard(DiscardReason::Malformed));
        };
        let (destination_id, source_id) = match packet.header {
            Header::UnsupportedVersion {
                destination_id,
                source_id,
                ..
            } => (destination_id, source_id),
            Header::VersionNegotiation { .. } => {
                return Ok(ListenerAction::Discard(DiscardReason::VersionNegotiation));
            }
            _ => return Ok(ListenerAction::Discard(DiscardReason::SupportedVersion)),
        };
        if self.prepared == self.max_responses {
            return Ok(ListenerAction::Discard(DiscardReason::RateLimited));
        }
        // Invariant length octets limit the sum to 510. With one version, the
        // result is <=521 and strictly smaller than every admitted datagram.
        let len = 7 + destination_id.len() + source_id.len() + 4;
        if out.len() < len {
            return Err(Error::Capacity);
        }
        let mut unused = [0];
        rng.try_fill_bytes(&mut unused)
            .map_err(|_| Error::Entropy)?;
        out[0] = 0xc0 | (unused[0] & 0x3f);
        out[1..5].fill(0);
        out[5] = source_id.len() as u8;
        let source_end = 6 + source_id.len();
        out[6..source_end].copy_from_slice(source_id);
        out[source_end] = destination_id.len() as u8;
        let destination_end = source_end + 1 + destination_id.len();
        out[source_end + 1..destination_end].copy_from_slice(destination_id);
        out[destination_end..len].copy_from_slice(&QUIC_V1.to_be_bytes());
        // This cannot overflow: prepared < max_responses <= u32::MAX.
        self.prepared += 1;
        Ok(ListenerAction::Send { len })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientState {
    InitialNotSent,
    AwaitingPeer,
    PeerPacketProcessed,
    Abandoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IgnoreReason {
    InitialNotSent,
    PeerPacketProcessed,
    AlreadyAbandoned,
    TooLarge,
    MalformedOrNotVersionNegotiation,
    ConnectionIdMismatch,
    OfferedVersionPresent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAction {
    Ignore(IgnoreReason),
    /// Unauthenticated no-common-version indication. Retire this attempt without
    /// a wire response; never select a different version or restart this object.
    Abandon,
}

/// One v1 connection attempt. Deliberately not Clone or resettable.
#[derive(Debug)]
pub struct Client {
    original_destination: [u8; 20],
    original_len: u8,
    local_source: [u8; 20],
    local_len: u8,
    state: ClientState,
}

impl Client {
    pub fn new(original_destination_id: &[u8], client_source_id: &[u8]) -> Result<Self, Error> {
        if !(8..=20).contains(&original_destination_id.len()) || client_source_id.len() > 20 {
            return Err(Error::InvalidConnectionId);
        }
        let mut result = Self {
            original_destination: [0; 20],
            original_len: original_destination_id.len() as u8,
            local_source: [0; 20],
            local_len: client_source_id.len() as u8,
            state: ClientState::InitialNotSent,
        };
        result.original_destination[..original_destination_id.len()]
            .copy_from_slice(original_destination_id);
        result.local_source[..client_source_id.len()].copy_from_slice(client_source_id);
        Ok(result)
    }

    pub fn state(&self) -> ClientState {
        self.state
    }

    /// The engine has validated the descriptor and actual Initial submission.
    /// Duplicate reports cannot reopen a closed or abandoned VN window.
    pub fn on_initial_accepted(&mut self) {
        if self.state == ClientState::InitialNotSent {
            self.state = ClientState::AwaitingPeer;
        }
    }

    /// Call for any successfully processed server packet, including a validated
    /// Retry. Retry's public integrity constant does not authenticate the server.
    pub fn on_peer_processed(&mut self) {
        if self.state != ClientState::Abandoned {
            self.state = ClientState::PeerPacketProcessed;
        }
    }

    pub fn on_packet(&mut self, datagram: &[u8]) -> ClientAction {
        match self.state {
            ClientState::InitialNotSent => {
                return ClientAction::Ignore(IgnoreReason::InitialNotSent);
            }
            ClientState::PeerPacketProcessed => {
                return ClientAction::Ignore(IgnoreReason::PeerPacketProcessed);
            }
            ClientState::Abandoned => {
                return ClientAction::Ignore(IgnoreReason::AlreadyAbandoned);
            }
            ClientState::AwaitingPeer => {}
        }
        if datagram.len() > MAX_DATAGRAM_BYTES {
            return ClientAction::Ignore(IgnoreReason::TooLarge);
        }
        let parsed = PacketIter::new(datagram, 0, 1)
            .ok()
            .and_then(|mut packets| packets.next())
            .and_then(Result::ok);
        let Some(Header::VersionNegotiation {
            destination_id,
            source_id,
            versions,
        }) = parsed.map(|packet| packet.header)
        else {
            return ClientAction::Ignore(IgnoreReason::MalformedOrNotVersionNegotiation);
        };
        if destination_id != &self.local_source[..usize::from(self.local_len)]
            || source_id != &self.original_destination[..usize::from(self.original_len)]
        {
            return ClientAction::Ignore(IgnoreReason::ConnectionIdMismatch);
        }
        if versions.iter().any(|version| version == QUIC_V1) {
            return ClientAction::Ignore(IgnoreReason::OfferedVersionPresent);
        }
        self.state = ClientState::Abandoned;
        ClientAction::Abandon
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Entropy {
        byte: u8,
        calls: usize,
        fail: bool,
    }
    impl RngCore for Entropy {
        fn next_u32(&mut self) -> u32 {
            panic!("try_fill_bytes required")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("try_fill_bytes required")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("try_fill_bytes required")
        }
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
            self.calls += 1;
            if self.fail {
                return Err(core::num::NonZeroU32::new(1).unwrap().into());
            }
            out.fill(self.byte);
            self.byte = self.byte.wrapping_add(1);
            Ok(())
        }
    }
    // Deterministic test-only source; production callers inject actual entropy.
    impl CryptoRng for Entropy {}
    fn entropy() -> Entropy {
        Entropy {
            byte: 0x2d,
            calls: 0,
            fail: false,
        }
    }
    fn trigger(destination: &[u8], source: &[u8], version: u32, first: u8) -> [u8; 1200] {
        let mut out = [0; 1200];
        out[0] = first;
        out[1..5].copy_from_slice(&version.to_be_bytes());
        out[5] = destination.len() as u8;
        out[6..6 + destination.len()].copy_from_slice(destination);
        let at = 6 + destination.len();
        out[at] = source.len() as u8;
        out[at + 1..at + 1 + source.len()].copy_from_slice(source);
        out
    }
    fn vn<'a>(
        out: &'a mut [u8],
        destination: &[u8],
        source: &[u8],
        versions: &[u32],
        unused: u8,
    ) -> &'a [u8] {
        out[0] = 0x80 | unused;
        out[1..5].fill(0);
        out[5] = destination.len() as u8;
        out[6..6 + destination.len()].copy_from_slice(destination);
        let mut at = 6 + destination.len();
        out[at] = source.len() as u8;
        at += 1;
        out[at..at + source.len()].copy_from_slice(source);
        at += source.len();
        for v in versions {
            out[at..at + 4].copy_from_slice(&v.to_be_bytes());
            at += 4;
        }
        &out[..at]
    }
    fn client() -> Client {
        let mut c = Client::new(b"original", b"client").unwrap();
        c.on_initial_accepted();
        c
    }
    fn listener() -> Listener {
        Listener::new(1200, 64, 1_000_000).unwrap()
    }

    #[test]
    fn listener_swaps_cids_and_emits_only_v1_with_real_rng_contract() {
        let input = trigger(b"original", b"client", 0x6b33_43cf, 0x80);
        let mut out = [0xaa; MAX_RESPONSE_BYTES];
        let mut rng = entropy();
        let ListenerAction::Send { len } = listener()
            .on_datagram(0, &input, &mut rng, &mut out)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(len, 25);
        assert_eq!(out[0], 0xed);
        assert_eq!(rng.calls, 1);
        assert!(out[len..].iter().all(|&b| b == 0xaa));
        let packet = PacketIter::new(&out[..len], 0, 1)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let Header::VersionNegotiation {
            destination_id,
            source_id,
            versions,
        } = packet.header
        else {
            panic!()
        };
        assert_eq!(destination_id, b"client");
        assert_eq!(source_id, b"original");
        assert_eq!(versions.as_bytes(), 1_u32.to_be_bytes());
        assert!(len < input.len());
    }

    #[test]
    fn invariant_cids_zero_through_255_and_all_unknown_header_bits_work() {
        let cid = [0x57; 255];
        for d in [0, 1, 20, 21, 255] {
            for s in [0, 1, 20, 21, 255] {
                for bits in [0, 0x0f, 0x30, 0x40, 0x7f] {
                    let input = trigger(&cid[..d], &cid[..s], 0x0a0a_0a0a, 0x80 | bits);
                    let mut out = [0; MAX_RESPONSE_BYTES];
                    let ListenerAction::Send { len } = listener()
                        .on_datagram(0, &input, &mut entropy(), &mut out)
                        .unwrap()
                    else {
                        panic!()
                    };
                    assert_eq!(len, 11 + d + s);
                    assert!(len <= MAX_RESPONSE_BYTES);
                    let p = PacketIter::new(&out[..len], 0, 1)
                        .unwrap()
                        .next()
                        .unwrap()
                        .unwrap();
                    assert!(
                        matches!(p.header, Header::VersionNegotiation { destination_id, source_id, .. } if destination_id == &cid[..s] && source_id == &cid[..d])
                    );
                }
            }
        }
    }

    #[test]
    fn undersized_oversized_short_supported_and_vn_do_not_reflect() {
        let input = trigger(b"original", b"client", 2, 0x80);
        let mut state = listener();
        let mut rng = entropy();
        let mut out = [0xa5; MAX_RESPONSE_BYTES];
        for n in 0..1200 {
            assert_eq!(
                state.on_datagram(0, &input[..n], &mut rng, &mut out),
                Ok(ListenerAction::Discard(DiscardReason::TooSmall))
            );
        }
        assert_eq!(
            state.on_datagram(0, &[0; 1201], &mut rng, &mut out),
            Ok(ListenerAction::Discard(DiscardReason::TooLarge))
        );
        let short = trigger(b"original", b"client", 2, 0x40);
        assert_eq!(
            state.on_datagram(0, &short, &mut rng, &mut out),
            Ok(ListenerAction::Discard(DiscardReason::ShortHeader))
        );
        let supported = trigger(b"original", b"client", 1, 0xc0);
        assert!(matches!(
            state.on_datagram(0, &supported, &mut rng, &mut out),
            Ok(ListenerAction::Discard(_))
        ));
        // 1200 - 7 - 1 = 1192, a complete nonempty supported-version list.
        let negotiation = trigger(&[7], &[], 0, 0x80);
        assert_eq!(
            state.on_datagram(0, &negotiation, &mut rng, &mut out),
            Ok(ListenerAction::Discard(DiscardReason::VersionNegotiation))
        );
        assert_eq!(rng.calls, 0);
        assert_eq!(out, [0xa5; MAX_RESPONSE_BYTES]);
    }

    #[test]
    fn one_response_per_invocation_and_fixed_window_quota_never_refunds() {
        let input = trigger(b"original", b"client", 2, 0x80);
        let mut state = Listener::new(1200, 2, 10).unwrap();
        let mut rng = entropy();
        let mut out = [0; MAX_RESPONSE_BYTES];
        for now in [0, 1] {
            assert!(matches!(
                state.on_datagram(now, &input, &mut rng, &mut out),
                Ok(ListenerAction::Send { .. })
            ));
            // No refund API exists, including if the adapter rejects submission.
        }
        for now in [1, 9] {
            assert_eq!(
                state.on_datagram(now, &input, &mut rng, &mut out),
                Ok(ListenerAction::Discard(DiscardReason::RateLimited))
            );
        }
        assert!(matches!(
            state.on_datagram(10, &input, &mut rng, &mut out),
            Ok(ListenerAction::Send { .. })
        ));
        assert_eq!(rng.calls, 3);
        assert_eq!(
            state.on_datagram(9, &input, &mut rng, &mut out),
            Err(Error::TimeWentBackwards)
        );
        assert_eq!(state.prepared, 1);
    }

    #[test]
    fn all_output_capacities_and_entropy_failure_are_atomic() {
        let input = trigger(b"original", b"client", 2, 0x80);
        let mut state = listener();
        let mut rng = entropy();
        let mut out = [0xa5; MAX_RESPONSE_BYTES];
        for capacity in 0..25 {
            assert_eq!(
                state.on_datagram(0, &input, &mut rng, &mut out[..capacity]),
                Err(Error::Capacity)
            );
            assert_eq!(state.prepared, 0);
            assert_eq!(out, [0xa5; MAX_RESPONSE_BYTES]);
        }
        assert_eq!(rng.calls, 0);
        rng.fail = true;
        assert_eq!(
            state.on_datagram(0, &input, &mut rng, &mut out),
            Err(Error::Entropy)
        );
        assert_eq!(state.prepared, 0);
        assert_eq!(out, [0xa5; MAX_RESPONSE_BYTES]);
        rng.fail = false;
        assert!(matches!(
            state.on_datagram(0, &input, &mut rng, &mut out),
            Ok(ListenerAction::Send { len: 25 })
        ));
    }

    #[test]
    fn config_and_time_boundaries_are_checked_without_clock_overflow() {
        for (bytes, quota, window) in [
            (1199, 1, 1),
            (MAX_DATAGRAM_BYTES + 1, 1, 1),
            (1200, 0, 1),
            (1200, 1, 0),
        ] {
            assert!(matches!(
                Listener::new(bytes, quota, window),
                Err(Error::InvalidConfiguration)
            ));
        }
        let mut state = Listener::new(1200, 1, u64::MAX).unwrap();
        let input = trigger(b"original", b"client", 2, 0x80);
        let mut out = [0; MAX_RESPONSE_BYTES];
        assert!(matches!(
            state.on_datagram(u64::MAX - 1, &input, &mut entropy(), &mut out),
            Ok(ListenerAction::Send { .. })
        ));
        assert_eq!(
            state.on_datagram(u64::MAX, &input, &mut entropy(), &mut out),
            Ok(ListenerAction::Discard(DiscardReason::RateLimited))
        );
    }

    #[test]
    fn client_abandons_without_any_version_restart_and_cannot_reopen() {
        let mut out = [0; 128];
        let packet = vn(
            &mut out,
            b"client",
            b"original",
            &[0x6b33_43cf, 0x0a0a_0a0a],
            0,
        );
        let mut client = client();
        assert_eq!(client.on_packet(packet), ClientAction::Abandon);
        assert_eq!(client.state(), ClientState::Abandoned);
        client.on_initial_accepted();
        client.on_peer_processed();
        assert_eq!(
            client.on_packet(packet),
            ClientAction::Ignore(IgnoreReason::AlreadyAbandoned)
        );
    }

    #[test]
    fn offered_v1_anywhere_in_list_is_ignored_without_consuming_window() {
        let mut out = [0; 128];
        let mut client = client();
        for versions in [&[1][..], &[1, 2], &[2, 1], &[0, 2, 1, 0x0a0a_0a0a], &[1, 1]] {
            assert_eq!(
                client.on_packet(vn(&mut out, b"client", b"original", versions, 0)),
                ClientAction::Ignore(IgnoreReason::OfferedVersionPresent)
            );
            assert_eq!(client.state(), ClientState::AwaitingPeer);
        }
        assert_eq!(
            client.on_packet(vn(&mut out, b"client", b"original", &[2], 0)),
            ClientAction::Abandon
        );
    }

    #[test]
    fn either_wrong_cid_is_ignored_and_zero_client_cid_is_supported() {
        let mut out = [0; 128];
        let mut client = client();
        for (dcid, scid) in [
            (b"wrong!".as_slice(), b"original".as_slice()),
            (b"client".as_slice(), b"wrongcid".as_slice()),
        ] {
            assert_eq!(
                client.on_packet(vn(&mut out, dcid, scid, &[2], 0)),
                ClientAction::Ignore(IgnoreReason::ConnectionIdMismatch)
            );
        }
        let mut zero = Client::new(b"original", &[]).unwrap();
        zero.on_initial_accepted();
        assert_eq!(
            zero.on_packet(vn(&mut out, &[], b"original", &[2], 0)),
            ClientAction::Abandon
        );
    }

    #[test]
    fn unsent_or_processed_peer_including_retry_prevents_vn_acceptance() {
        let mut out = [0; 128];
        let packet = vn(&mut out, b"client", b"original", &[2], 0);
        let mut client = Client::new(b"original", b"client").unwrap();
        assert_eq!(
            client.on_packet(packet),
            ClientAction::Ignore(IgnoreReason::InitialNotSent)
        );
        client.on_initial_accepted();
        client.on_peer_processed();
        client.on_initial_accepted();
        assert_eq!(
            client.on_packet(packet),
            ClientAction::Ignore(IgnoreReason::PeerPacketProcessed)
        );
        assert_eq!(client.state(), ClientState::PeerPacketProcessed);
    }

    #[test]
    fn client_ignores_all_unused_header_bits_and_rejects_truncated_lists() {
        let mut out = [0; 128];
        for unused in 0..=127 {
            assert_eq!(
                client().on_packet(vn(&mut out, b"client", b"original", &[2], unused)),
                ClientAction::Abandon
            );
        }
        let packet = vn(&mut out, b"client", b"original", &[2], 0);
        for end in 0..packet.len() {
            let mut client = client();
            assert_eq!(
                client.on_packet(&packet[..end]),
                ClientAction::Ignore(IgnoreReason::MalformedOrNotVersionNegotiation)
            );
            assert_eq!(client.state(), ClientState::AwaitingPeer);
        }
        let mut padded = [0; 128];
        padded[..packet.len()].copy_from_slice(packet);
        for extra in 1..4 {
            assert_eq!(
                client().on_packet(&padded[..packet.len() + extra]),
                ClientAction::Ignore(IgnoreReason::MalformedOrNotVersionNegotiation)
            );
        }
    }

    #[test]
    fn client_configuration_is_v1_only_and_long_vn_cids_cannot_match() {
        assert!(matches!(
            Client::new(&[0; 7], &[]),
            Err(Error::InvalidConnectionId)
        ));
        assert!(matches!(
            Client::new(&[0; 21], &[]),
            Err(Error::InvalidConnectionId)
        ));
        assert!(matches!(
            Client::new(&[0; 8], &[0; 21]),
            Err(Error::InvalidConnectionId)
        ));
        let mut out = [0; MAX_RESPONSE_BYTES];
        assert_eq!(
            client().on_packet(vn(&mut out, &[0; 255], &[0; 255], &[2], 0)),
            ClientAction::Ignore(IgnoreReason::ConnectionIdMismatch)
        );
    }
}
