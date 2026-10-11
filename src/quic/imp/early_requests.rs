//! Bounded early request bytes, publication receipts and replay views.
use crate::crypto::directional::ApplicationKeyScope;
use crate::quic::Error;
use crate::quic::application::{ClientRequests, MAX_REQUEST_BYTES};
use crate::quic::early_data::imp::EarlyStatus;
use crate::quic::early_data::imp::RememberedLimits;
use crate::quic::imp::kernel::packet;
use crate::quic::imp::kernel::packet::Frame;
use hibana_tls::handshake::keys::FinishedAuthenticated;
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
    pub(in crate::quic) fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub(in crate::quic) fn max_udp_payload(&self) -> u64 {
        self.remembered.max_udp_payload()
    }

    pub(crate) fn new(
        scope: &'scope ApplicationKeyScope,
        slots: &'a mut [RequestSlot],
        remembered: RememberedLimits,
        publication_slots: usize,
        chunk_bytes: usize,
    ) -> Result<Self, Error> {
        if slots.is_empty()
            || slots.len() > crate::quic::application::imp::stream::MAX_LIVE_STREAMS
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

    pub(in crate::quic) fn capacity(&self) -> usize {
        self.slots.len()
    }
    pub(in crate::quic) fn input_buffer(&mut self, index: usize) -> Result<&mut [u8], Error> {
        if index != self.len {
            return Err(Error::Binding);
        }
        let slot = self.slots.get_mut(index).ok_or(Error::Capacity)?;
        if slot.len != 0 || slot.accepted.is_some() {
            return Err(Error::Binding);
        }
        Ok(&mut slot.bytes)
    }
    pub(in crate::quic) fn retain_input(&mut self, index: usize, len: usize) -> Result<(), Error> {
        if index != self.len {
            return Err(Error::Binding);
        }
        let slot = self.slots.get_mut(index).ok_or(Error::Capacity)?;
        if len > MAX_REQUEST_BYTES || !replay_safe_get(&slot.bytes[..len]) {
            return Err(Error::Tls(hibana_tls::quic::Error::InvalidInput));
        }
        slot.len = len;
        self.len += 1;
        Ok(())
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

#[cfg(test)]
#[path = "early_requests_tests.rs"]
mod tests;
