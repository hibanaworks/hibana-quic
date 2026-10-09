//! Bounded client request intent retained across the authenticated early decision.
//! These bytes do not authorize publication or successful delivery. Only the
//! projected wire role may attach evidence of an actual accepted UDP send.
use super::Error;
use super::application::{ClientRequests, MAX_REQUEST_BYTES};
use crate::crypto::directional::ApplicationKeyScope;
use crate::quic::early_data::imp::EarlyStatus;
use crate::quic::early_data::imp::RememberedLimits;
use crate::quic::imp::kernel::packet;
use crate::quic::imp::kernel::packet::Frame;
use hibana_tls::handshake::local::keys::FinishedAuthenticated;
use hibana_tls::secret::Erase;

pub struct RequestSlot {
    bytes: [u8; MAX_REQUEST_BYTES],
    len: usize,
    accepted: Option<Accepted>,
}
// Private data receipt: no Clone/Copy and no constructor outside this module.
struct Accepted {
    packet_number: u64,
    plaintext_digest: [u8; 32],
}
impl RequestSlot {
    pub const EMPTY: Self = Self {
        bytes: [0; MAX_REQUEST_BYTES],
        len: 0,
        accepted: None,
    };
}
impl Drop for RequestSlot {
    fn drop(&mut self) {
        self.bytes.erase();
    }
}

pub struct Requests<'a, 'scope> {
    scope: &'scope ApplicationKeyScope,
    slots: &'a mut [RequestSlot],
    len: usize,
    remembered: RememberedLimits,
    publication_slots: usize,
    chunk_bytes: usize,
}
impl<'a, 'scope> Requests<'a, 'scope> {
    pub(crate) fn new(
        scope: &'scope ApplicationKeyScope,
        slots: &'a mut [RequestSlot],
        remembered: RememberedLimits,
        publication_slots: usize,
        chunk_bytes: usize,
    ) -> Result<Self, Error> {
        if slots.is_empty()
            || slots.len() > super::stream::MAX_LIVE_STREAMS
            || slots
                .iter()
                .any(|slot| slot.len != 0 || slot.accepted.is_some())
        {
            return Err(Error::Capacity);
        }
        Ok(Self {
            scope,
            slots,
            len: 0,
            remembered,
            publication_slots,
            chunk_bytes,
        })
    }

    /// Pair each pending request with exactly one started callback. These are
    /// planned client-bidirectional IDs, materialized by the application owner
    /// after Finished. Rejection does not call started again or reuse an ID.
    pub(crate) async fn prepare(&mut self, input: &mut impl ClientRequests) -> Result<(), Error> {
        if self.len != 0 {
            return Err(Error::Binding);
        }
        for index in 0..self.slots.len() {
            let slot = &mut self.slots[index];
            let Some(len) = input
                .next(&mut slot.bytes)
                .await
                .map_err(|_| Error::Tls(hibana_tls::endpoint::Error::InvalidInput))?
            else {
                return Ok(());
            };
            if len > MAX_REQUEST_BYTES || !replay_safe_get(&slot.bytes[..len]) {
                return Err(Error::Tls(hibana_tls::endpoint::Error::InvalidInput));
            }
            // Retain the intent before acknowledging consumption to its owner.
            slot.len = len;
            input
                .started((index as u64) * 4)
                .map_err(|_| Error::Tls(hibana_tls::endpoint::Error::InvalidInput))?;
            self.len += 1;
        }
        let mut excess = [0; MAX_REQUEST_BYTES];
        let more = input
            .next(&mut excess)
            .await
            .map_err(|_| Error::Tls(hibana_tls::endpoint::Error::InvalidInput))?;
        excess.erase();
        if more.is_some() {
            Err(Error::Capacity)
        } else {
            Ok(())
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
    pub(crate) fn bytes(&self, index: usize) -> Result<&[u8], Error> {
        let slot = self
            .slots
            .get(index)
            .filter(|_| index < self.len)
            .ok_or(Error::Binding)?;
        Ok(&slot.bytes[..slot.len])
    }

    /// Select a prefix under the remembered transport limits. An unsent suffix
    /// remains intact for normal 1-RTT admission; no request is silently dropped.
    pub(crate) fn encode(&self, index: usize, output: &mut [u8]) -> Result<Option<usize>, Error> {
        let limits = self.remembered.stream_limits();
        let bytes = self.bytes(index)?;
        let total: u64 = self.slots[..=index]
            .iter()
            .map(|slot| slot.len as u64)
            .sum();
        if index >= self.publication_slots
            || bytes.len() > self.chunk_bytes
            || index as u64 >= limits.max_streams_bidi
            || bytes.len() as u64 > limits.stream_data_bidi_remote
            || total > limits.max_data
        {
            return Ok(None);
        }
        Ok(Some(packet::encode_frame(
            &Frame::Stream {
                id: (index as u64) * 4,
                offset: 0,
                fin: true,
                data: bytes,
            },
            output,
        )?))
    }

    pub(crate) fn accepted(
        &mut self,
        index: usize,
        packet_number: u64,
        plaintext: &[u8],
    ) -> Result<(), Error> {
        let mut expected = [0; MAX_REQUEST_BYTES + 32];
        let len = self.encode(index, &mut expected)?.ok_or(Error::Binding)?;
        if plaintext != &expected[..len]
            || packet_number > crate::quic::imp::kernel::streams::MAX_OFFSET
            || self.slots[..self.len].iter().any(|slot| {
                slot.accepted
                    .as_ref()
                    .is_some_and(|v| v.packet_number == packet_number)
            })
        {
            return Err(Error::Binding);
        }
        let slot = &mut self.slots[index];
        if slot.accepted.is_some() {
            return Err(Error::Binding);
        }
        slot.accepted = Some(Accepted {
            packet_number,
            plaintext_digest: crate::crypto::plaintext_digest(plaintext),
        });
        Ok(())
    }

    pub(crate) fn accepted_count(&self) -> usize {
        self.slots[..self.len]
            .iter()
            .take_while(|slot| slot.accepted.is_some())
            .count()
    }
    pub(crate) fn accepted_packet(&self, index: usize, plaintext: &[u8]) -> Result<u64, Error> {
        let receipt = self
            .slots
            .get(index)
            .and_then(|slot| slot.accepted.as_ref())
            .ok_or(Error::Binding)?;
        if receipt.plaintext_digest != crate::crypto::plaintext_digest(plaintext) {
            return Err(Error::Binding);
        }
        Ok(receipt.packet_number)
    }
    pub(crate) fn validate_accepted_limits(&self, peer: &[u8]) -> Result<(), Error> {
        let current = RememberedLimits::from_authenticated_server_parameters(peer)
            .map_err(|_| Error::Binding)?;
        current
            .permits_early_from(self.remembered)
            .map_err(|_| Error::Binding)
    }
    pub(crate) fn replay(&self, consumed: usize) -> Replay<'_, 'a, 'scope> {
        Replay {
            requests: self,
            next: consumed,
        }
    }
    pub(crate) fn decision(
        &self,
        finished: &FinishedAuthenticated<'_>,
    ) -> Result<EarlyStatus, Error> {
        if !core::ptr::eq(self.scope, finished.scope())
            || finished.side() != hibana_tls::schedule::Side::Client
            || !matches!(
                finished.early_status(),
                EarlyStatus::Accepted | EarlyStatus::Rejected
            )
        {
            return Err(Error::Binding);
        }
        Ok(finished.early_status())
    }
}

pub(crate) struct Replay<'r, 'a, 'scope> {
    requests: &'r Requests<'a, 'scope>,
    next: usize,
}
impl ClientRequests for Replay<'_, '_, '_> {
    async fn next(&mut self, output: &mut [u8]) -> Result<Option<usize>, ()> {
        if self.next == self.requests.len() {
            return Ok(None);
        }
        let bytes = self.requests.bytes(self.next).map_err(|_| ())?;
        if bytes.len() > output.len() {
            return Err(());
        }
        output[..bytes.len()].copy_from_slice(bytes);
        Ok(Some(bytes.len()))
    }
    fn started(&mut self, id: u64) -> Result<(), ()> {
        if self.next >= self.requests.len() || id != self.next as u64 * 4 {
            return Err(());
        }
        self.next += 1;
        Ok(())
    }
}

fn replay_safe_get(bytes: &[u8]) -> bool {
    let Some(path) = bytes
        .strip_prefix(b"GET ")
        .and_then(|v| v.strip_suffix(b"\r\n"))
    else {
        return false;
    };
    path.starts_with(b"/")
        && !path
            .iter()
            .any(|byte| byte.is_ascii_control() || *byte == b' ')
}

use super::{
    Clock, Config, DatagramTx, Outcome, Roles, Side, global as p, initial, publication_gate,
    recovery,
    tls::{CryptoFlight, Inbox, Transcript},
    wire,
};
use core::pin::pin;
use hibana::{g::Message, runtime::resolver::DecisionArm};
use hibana_tls::endpoint::Level;
use hibana_tls::handshake::local::keys::EarlyKeyMaterial;
use hibana_tls::handshake::local::keys::TransmitPacketKey;

/// One finite projected prefix. Normal handshakes traverse the explicit Skip
/// edges; an enabled client sends ClientHello before any early datagram.
#[allow(clippy::too_many_arguments)]
pub(in crate::quic) async fn run<'book, 'scope, const N: usize>(
    roles: &mut Roles<'_>,
    source: &mut Transcript<'scope, '_, '_>,
    requests: Option<&mut Requests<'_, 'scope>>,
    config: Config<'_>,
    initial: &initial::Keys<'scope>,
    tx: &mut recovery::Tx<'book, 'scope, N>,
    publication: &mut recovery::Publication<'book, 'scope, N>,
    io: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut publication_gate::Issuer<'_, 'scope>,
    outcome: &Outcome,
) -> Result<(), Error> {
    let enabled = requests.is_some();
    let prepared = Inbox::<(CryptoFlight<N>, TransmitPacketKey<'scope>)>::new();
    let datagrams = Inbox::<wire::Datagram<'book, N>>::new();
    let scope = source.scope();
    let mut prepare = pin!(async {
        if !enabled {
            roles.tls_tx.send::<p::EarlySkip>(&()).await?;
            roles.tls_tx.send::<p::EarlyContinue>(&()).await?;
            return Ok(());
        }
        if config.side != Side::Client || source.early_status() != EarlyStatus::Offered {
            return Err(Error::Binding);
        }
        let EarlyKeyMaterial::Transmit(key) = source.take_early_key()? else {
            return Err(Error::Binding);
        };
        let flight = source.transmit::<N>()?.ok_or(Error::Binding)?;
        if flight.level() != Level::Initial || flight.offset() != 0 {
            return Err(Error::Binding);
        }
        prepared.put((flight, key))?;
        roles.tls_tx.send::<p::EarlyStart>(&()).await?;
        roles.tls_tx.recv::<p::EarlyDone>().await?;
        roles.tls_tx.send::<p::EarlyContinue>(&()).await?;
        Ok(())
    });
    let mut wire = pin!(async {
        let edge = roles.tx_wire.offer().await?;
        if edge.label() == p::EarlySkip::LOGICAL_LABEL {
            edge.recv::<p::EarlySkip>().await?;
            roles.tx_wire.send::<p::EarlySkip>(&()).await?;
            return Ok(());
        }
        edge.recv::<p::EarlyStart>().await?;
        let requests = requests.ok_or(Error::Binding)?;
        if !core::ptr::eq(requests.scope, scope) {
            return Err(Error::Binding);
        }
        let (flight, mut key) = prepared.take()?;
        roles.tx_wire.send::<p::EarlyStart>(&()).await?;
        let flight_id = tx.store_crypto(Level::Initial, flight.offset(), flight.bytes())?;
        let peer = super::ConnectionId::new(config.peer_connection_id)?;
        let plain = wire::PlainPacket::<N>::new(
            config,
            &peer,
            Level::Initial,
            Frame::Crypto {
                offset: flight.offset(),
                data: flight.bytes(),
            },
        )?;
        let reservation = tx.reserve(
            Level::Initial,
            plain.len() as u64,
            Some(flight_id),
            true,
            plain.padded(),
            false,
            clock.now(),
        )?;
        let initial_packet = match initial.seal(plain, reservation, None) {
            Ok(packet) => packet,
            Err((error, reservation)) => {
                tx.cancel(reservation)?;
                return Err(error);
            }
        };
        async {
            let endpoint = &mut roles.tx_wire;
            let slot = &datagrams;
            let packet = initial_packet;

            slot.put(packet)?;
            endpoint.send::<p::EarlyInitialDatagram>(&()).await?;
            let edge = endpoint.offer().await?;
            let accepted = if edge.label() == p::EarlyInitialAccepted::LOGICAL_LABEL {
                edge.recv::<p::EarlyInitialAccepted>().await?;
                true
            } else {
                edge.recv::<p::EarlyInitialRejected>().await?;
                false
            };
            endpoint.send::<p::EarlyInitialSettled>(&()).await?;
            if accepted {
                Ok::<(), Error>(())
            } else {
                Err(Error::Io(super::IoError::Rejected))
            }
        }
        .await?;
        for index in 0..requests.len() {
            let mut plaintext = [0; N];
            let Some(len) = requests.encode(index, &mut plaintext)? else {
                break;
            };
            let size = super::early_wire::encoded_len(
                config.peer_connection_id,
                config.local_connection_id,
                len,
            )?;
            if size > N || size as u64 > requests.remembered.max_udp_payload() {
                break;
            }
            let reservation =
                match tx.reserve_early(&key, &plaintext[..len], size as u64, clock.now()) {
                    Ok(reservation) => reservation,
                    Err(
                        recovery::Error::CongestionLimited
                        | recovery::Error::Accounting(
                            crate::quic::imp::kernel::accounting::AccountingError::Full,
                        ),
                    ) => break,
                    Err(error) => return Err(error.into()),
                };
            let pn = reservation.packet().value;
            let sealed = match super::early_wire::seal::<N>(
                &mut key,
                reservation,
                config.peer_connection_id,
                config.local_connection_id,
                &plaintext[..len],
            ) {
                Ok(packet) => packet,
                Err((error, reservation)) => {
                    tx.cancel(reservation)?;
                    return Err(error);
                }
            };
            async {
                let endpoint = &mut roles.tx_wire;
                let slot = &datagrams;
                let packet = wire::Datagram::from_early(sealed);

                slot.put(packet)?;
                endpoint.send::<p::EarlyPacketDatagram>(&()).await?;
                let edge = endpoint.offer().await?;
                let accepted = if edge.label() == p::EarlyPacketAccepted::LOGICAL_LABEL {
                    edge.recv::<p::EarlyPacketAccepted>().await?;
                    true
                } else {
                    edge.recv::<p::EarlyPacketRejected>().await?;
                    false
                };
                endpoint.send::<p::EarlyPacketSettled>(&()).await?;
                if accepted {
                    Ok::<(), Error>(())
                } else {
                    Err(Error::Io(super::IoError::Rejected))
                }
            }
            .await?;
            requests.accepted(index, pn, &plaintext[..len])?;
            plaintext.erase();
        }
        drop(key);
        roles.tx_wire.send::<p::EarlyEnd>(&()).await?;
        roles.tx_wire.send::<p::EarlyDone>(&()).await?;
        Ok(())
    });
    let mut publish = pin!(async {
        let edge = roles.udp.offer().await?;
        if edge.label() == p::EarlySkip::LOGICAL_LABEL {
            edge.recv::<p::EarlySkip>().await?;
            return Ok(());
        }
        edge.recv::<p::EarlyStart>().await?;
        roles.udp.recv::<p::EarlyInitialDatagram>().await?;
        async {
            let endpoint = &mut roles.udp;
            let slot = &datagrams;
            let io = &mut *io;
            let book = &mut *publication;
            let issuer = &mut *issuer;

            let packet = slot.take()?;
            let permit = match issuer.begin() {
                Ok(permit) => permit,
                Err(error) => {
                    book.cancel(packet.reservation)?;
                    return Err(error.into());
                }
            };
            if !core::ptr::eq(permit.scope(), packet.reservation.scope()) {
                book.cancel(packet.reservation)?;
                return Err(Error::Binding);
            }
            let result = permit
                .submit(io.send(
                    packet.sealed.bytes(),
                    crate::quic::ecn::imp::Codepoint::NotEct,
                ))
                .await;
            let accepted = match result {
                Ok(Ok(time)) => Some(time),
                _ => None,
            };
            book.settle(recovery::Completion::from_adapter(
                packet.reservation,
                accepted,
                crate::quic::ecn::imp::Codepoint::NotEct,
            ))?;
            outcome.set(accepted.is_some())?;
            match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                DecisionArm::Left => endpoint.send::<p::EarlyInitialAccepted>(&()).await?,
                DecisionArm::Right => endpoint.send::<p::EarlyInitialRejected>(&()).await?,
            }
            endpoint.recv::<p::EarlyInitialSettled>().await?;
            outcome.clear();
            match result {
                Ok(Ok(_)) => Ok::<(), Error>(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            }
        }
        .await?;
        loop {
            let edge = roles.udp.offer().await?;
            if edge.label() == p::EarlyEnd::LOGICAL_LABEL {
                edge.recv::<p::EarlyEnd>().await?;
                return Ok(());
            }
            edge.recv::<p::EarlyPacketDatagram>().await?;
            async {
                let endpoint = &mut roles.udp;
                let slot = &datagrams;
                let io = &mut *io;
                let book = &mut *publication;
                let issuer = &mut *issuer;

                let packet = slot.take()?;
                let permit = match issuer.begin() {
                    Ok(permit) => permit,
                    Err(error) => {
                        book.cancel(packet.reservation)?;
                        return Err(error.into());
                    }
                };
                if !core::ptr::eq(permit.scope(), packet.reservation.scope()) {
                    book.cancel(packet.reservation)?;
                    return Err(Error::Binding);
                }
                let result = permit
                    .submit(io.send(
                        packet.sealed.bytes(),
                        crate::quic::ecn::imp::Codepoint::NotEct,
                    ))
                    .await;
                let accepted = match result {
                    Ok(Ok(time)) => Some(time),
                    _ => None,
                };
                book.settle(recovery::Completion::from_adapter(
                    packet.reservation,
                    accepted,
                    crate::quic::ecn::imp::Codepoint::NotEct,
                ))?;
                outcome.set(accepted.is_some())?;
                match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                    DecisionArm::Left => endpoint.send::<p::EarlyPacketAccepted>(&()).await?,
                    DecisionArm::Right => endpoint.send::<p::EarlyPacketRejected>(&()).await?,
                }
                endpoint.recv::<p::EarlyPacketSettled>().await?;
                outcome.clear();
                match result {
                    Ok(Ok(_)) => Ok::<(), Error>(()),
                    Ok(Err(error)) => Err(error.into()),
                    Err(error) => Err(error.into()),
                }
            }
            .await?;
        }
    });
    let mut resume = pin!(async {
        roles.tx.recv::<p::EarlyContinue>().await?;
        Ok::<(), Error>(())
    });
    crate::runtime::TaskSet::new([
        prepare.as_mut(),
        wire.as_mut(),
        publish.as_mut(),
        resume.as_mut(),
    ])
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    struct Input {
        next: usize,
        total: usize,
        pending: bool,
    }
    impl ClientRequests for Input {
        async fn next(&mut self, output: &mut [u8]) -> Result<Option<usize>, ()> {
            if self.pending {
                return Err(());
            }
            if self.next == self.total {
                return Ok(None);
            }
            output[..8].copy_from_slice(b"GET /x\r\n");
            self.pending = true;
            Ok(Some(8))
        }
        fn started(&mut self, id: u64) -> Result<(), ()> {
            if !self.pending || id != self.next as u64 * 4 {
                return Err(());
            }
            self.pending = false;
            self.next += 1;
            Ok(())
        }
    }
    fn ready<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("fixture unexpectedly pending"),
        }
    }
    fn limits() -> RememberedLimits {
        // Two bidi requests, total 16 bytes, 8 bytes per client-created stream.
        RememberedLimits::from_authenticated_server_parameters(&[
            0, 0, 15, 0, 4, 1, 16, 6, 1, 8, 8, 1, 2,
        ])
        .unwrap()
    }
    #[test]
    fn bounded_intent_keeps_unsent_suffix_and_pairs_callbacks_once() {
        let scope = ApplicationKeyScope::new(999);
        let mut slots = [const { RequestSlot::EMPTY }; 3];
        let mut requests =
            Requests::new(&scope, &mut slots, limits(), 3, MAX_REQUEST_BYTES).unwrap();
        let mut input = Input {
            next: 0,
            total: 3,
            pending: false,
        };
        ready(requests.prepare(&mut input)).unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(input.next, 3);
        let mut plain = [0; 64];
        let len = requests.encode(0, &mut plain).unwrap().unwrap();
        requests.accepted(0, 3, &plain[..len]).unwrap();
        assert!(matches!(
            requests.accepted(0, 3, &plain[..len]),
            Err(Error::Binding)
        ));
        assert!(requests.encode(1, &mut plain).unwrap().is_some());
        assert_eq!(requests.encode(2, &mut plain).unwrap(), None);
        assert_eq!(requests.bytes(2).unwrap(), b"GET /x\r\n");
        assert!(matches!(
            ready(requests.prepare(&mut input)),
            Err(Error::Binding)
        ));
        let mut replay = requests.replay(0);
        let mut bytes = [0; MAX_REQUEST_BYTES];
        for index in 0..3 {
            assert_eq!(ready(replay.next(&mut bytes)).unwrap(), Some(8));
            replay.started(index * 4).unwrap();
        }
        assert_eq!(ready(replay.next(&mut bytes)).unwrap(), None);
        assert_eq!(
            input.next, 3,
            "replay must not call the original started again"
        );
    }
    #[test]
    fn early_publication_is_bounded_by_actual_future_stream_storage() {
        let scope = ApplicationKeyScope::new(1000);
        for (slots_budget, chunk, expected) in [(1, 1024, true), (0, 1024, false), (2, 4, false)] {
            let mut slots = [const { RequestSlot::EMPTY }; 2];
            let mut requests =
                Requests::new(&scope, &mut slots, limits(), slots_budget, chunk).unwrap();
            let mut input = Input {
                next: 0,
                total: 2,
                pending: false,
            };
            ready(requests.prepare(&mut input)).unwrap();
            assert_eq!(
                requests.encode(0, &mut [0; 64]).unwrap().is_some(),
                expected
            );
            assert!(requests.encode(1, &mut [0; 64]).unwrap().is_none());
            assert_eq!(requests.bytes(1).unwrap(), b"GET /x\r\n");
        }
    }

    #[test]
    fn request_validation_rejects_mutation_and_line_injection() {
        assert!(replay_safe_get(b"GET /safe\r\n"));
        for bytes in [
            b"POST /x\r\n".as_slice(),
            b"GET /x\r\nGET /y\r\n",
            b"GET /x y\r\n",
            b"GET /x",
        ] {
            assert!(!replay_safe_get(bytes));
        }
    }
}
