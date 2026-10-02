//! Packet/TLS data marshalling to the one actual Provider-owning role.
//! No Provider implementation, key handle, synchronous polling, or substitute
//! protocol state machine is hidden in this endpoint-side capability plumbing.
use super::*;
use crate::roles::{packet_protection::Packet, tls_owner};

pub const TLS_PACKET_BYTES: usize = 1536;
pub const TLS_PARAMETER_BYTES: usize = 512;
pub type TlsClient<'channel, 'storage> =
    tls_owner::Client<'channel, 'storage, TLS_PACKET_BYTES, TLS_PARAMETER_BYTES, 1, 1>;
pub type TlsSnapshot = tls_owner::Snapshot<TLS_PARAMETER_BYTES>;

impl<'r, 's, 'tc, 'ts, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, 'tc, 'ts, K> {
    /// Last observation returned by the actual TLS owner. This snapshot never
    /// grants packet authentication, key-use, early release, or ACK authority.
    /// After terminal abort it remains the last observation, not a live owner.
    pub fn tls_snapshot(&self) -> &TlsSnapshot {
        self.tls
            .as_ref()
            .map_or(&self.tls_last, TlsClient::snapshot)
    }
    pub(super) fn tls_has_keys(&self, level: Level) -> bool {
        match level {
            Level::Initial => !self.discarded[0],
            Level::Handshake => self.tls_snapshot().handshake_keys,
            Level::OneRtt => self.tls_snapshot().one_rtt_keys,
        }
    }
    pub(super) fn abort_tls(&mut self) {
        if let Some(mut owner) = self.tls.take() {
            self.tls_last = *owner.snapshot();
            owner.close();
        }
    }
    pub(super) async fn retire_tls(&mut self) -> Result<(), Error> {
        if let Some(owner) = self.tls.take() {
            self.tls_last = *owner.snapshot();
            self.tls_last = owner.retire_snapshot().await?;
        }
        Ok(())
    }
    pub(super) async fn tls_mask(
        &mut self,
        level: Level,
        local: bool,
        sample: [u8; 16],
    ) -> Result<[u8; 5], Error> {
        Ok(self
            .tls
            .as_mut()
            .ok_or(Error::Retired)?
            .header_mask(level, local, sample)
            .await??)
    }
    pub(super) async fn tls_open(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        body: &mut [u8],
    ) -> Result<(usize, tls_owner::OpenReceipt), Error> {
        if level != Level::Handshake {
            return Err(Error::InvalidConfig);
        }
        let packet = Packet::new(pn, header, body)?;
        let opened = self
            .tls
            .as_mut()
            .ok_or(Error::Retired)?
            .open_handshake(packet)
            .await??;
        let len = opened.packet.body().len();
        body.get_mut(..len)
            .ok_or(Error::Capacity)?
            .copy_from_slice(opened.packet.body());
        Ok((len, opened.receipt))
    }
    pub(super) async fn tls_open_one_rtt(
        &mut self,
        pn: u64,
        phase: bool,
        header: &[u8],
        body: &mut [u8],
        now: u64,
        pto: u64,
    ) -> Result<(crypto::Opened, tls_owner::OpenReceipt), Error> {
        let packet = Packet::new(pn, header, body)?;
        let opened = self
            .tls
            .as_mut()
            .ok_or(Error::Retired)?
            .open_one_rtt(packet, phase, now, pto)
            .await??;
        let len = opened.packet.body().len();
        body.get_mut(..len)
            .ok_or(Error::Capacity)?
            .copy_from_slice(opened.packet.body());
        Ok((
            crypto::Opened {
                len,
                generation: opened.generation,
                key_updated: opened.key_updated,
            },
            opened.receipt,
        ))
    }
    pub(super) async fn tls_seal(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        body: &mut [u8],
        len: usize,
    ) -> Result<crate::roles::sealed_packet::SealedPacket<TLS_PACKET_BYTES>, Error> {
        let packet = Packet::new(pn, header, body.get(..len).ok_or(Error::Capacity)?)?;
        let owner = self.tls.as_mut().ok_or(Error::Retired)?;
        let packet = match level {
            Level::Handshake => owner.seal_handshake(packet).await??,
            Level::OneRtt => owner.seal_one_rtt(packet).await??,
            Level::Initial => return Err(Error::InvalidConfig),
        };
        body.get_mut(..packet.body().len())
            .ok_or(Error::Capacity)?
            .copy_from_slice(packet.body());
        Ok(packet)
    }
    pub(super) async fn tls_receive_crypto(
        &mut self,
        level: Level,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let previously_one_rtt = self.tls_snapshot().one_rtt_keys;
        self.tls
            .as_mut()
            .ok_or(Error::Retired)?
            .receive_crypto(level, bytes)
            .await??;
        if let Some(finished) = self
            .tls
            .as_mut()
            .ok_or(Error::Retired)?
            .take_finished_receipt()
        {
            if self.finished_receipt.is_some() {
                return Err(Error::ProtocolViolation);
            }
            self.finished_receipt = Some(finished);
        }
        if !previously_one_rtt && self.tls_snapshot().one_rtt_keys {
            self.trace_event(crate::trace::Event::ApplicationKeyUpdated {
                owner: self.trace_vantage(),
                generation: self.tls_snapshot().send_generation,
                trigger: crate::trace::KeyUpdateTrigger::Tls,
            });
            self.trace_event(crate::trace::Event::ApplicationKeyUpdated {
                owner: self.trace_peer_vantage(),
                generation: self.tls_snapshot().receive_generation,
                trigger: crate::trace::KeyUpdateTrigger::Tls,
            });
        }
        Ok(())
    }
    pub(super) async fn take_tls_flight(&mut self) -> Result<(), Error> {
        self.pending_tls = match self
            .tls
            .as_mut()
            .ok_or(Error::Retired)?
            .take_crypto_flight(self.pending_crypto.len())
            .await??
        {
            Some((level, bytes)) => {
                let n = bytes.as_bytes().len();
                self.pending_crypto
                    .get_mut(..n)
                    .ok_or(Error::Capacity)?
                    .copy_from_slice(bytes.as_bytes());
                Some(tls::Output { level, len: n })
            }
            None => None,
        };
        Ok(())
    }
    pub(super) async fn tls_confirm(
        &mut self,
        grant: crate::roles::path_owner::HandshakeConfirmation,
    ) -> Result<(), Error> {
        self.tls
            .as_mut()
            .ok_or(Error::Retired)?
            .confirm_handshake(grant)
            .await??;
        Ok(())
    }
    pub(super) async fn tls_acknowledge(
        &mut self,
        grant: crate::roles::recovery_owner::KeyAckGrant,
        now: u64,
        pto: u64,
    ) -> Result<(), Error> {
        self.tls
            .as_mut()
            .ok_or(Error::Retired)?
            .acknowledge_one_rtt(grant, now, pto)
            .await??;
        Ok(())
    }
    pub(super) async fn tls_maintain(&mut self, now: u64, pto: u64) -> Result<(), Error> {
        self.tls
            .as_mut()
            .ok_or(Error::Retired)?
            .maintain_keys(now, pto)
            .await??;
        Ok(())
    }
    pub(super) async fn tls_initiate_key_update(
        &mut self,
        now: u64,
        pto: u64,
    ) -> Result<(), Error> {
        self.tls
            .as_mut()
            .ok_or(Error::Retired)?
            .initiate_key_update(now, pto)
            .await??;
        Ok(())
    }
    pub(super) async fn tls_discard_handshake(&mut self) -> Result<(), Error> {
        self.tls
            .as_mut()
            .ok_or(Error::Retired)?
            .discard_handshake()
            .await??;
        Ok(())
    }
    pub(super) async fn tls_discard_early(&mut self) -> Result<(), Error> {
        self.tls
            .as_mut()
            .ok_or(Error::Retired)?
            .discard_early_keys()
            .await??;
        Ok(())
    }
    pub(super) async fn tls_early_mask(
        &mut self,
        local: bool,
        sample: [u8; 16],
    ) -> Result<[u8; 5], Error> {
        Ok(self
            .tls
            .as_mut()
            .ok_or(Error::Retired)?
            .early_header_mask(local, sample)
            .await??)
    }
    pub(super) async fn tls_seal_early(
        &mut self,
        pn: u64,
        header: &[u8],
        body: &mut [u8],
        len: usize,
    ) -> Result<(), Error> {
        let packet = Packet::new(pn, header, body.get(..len).ok_or(Error::Capacity)?)?;
        let packet = self
            .tls
            .as_mut()
            .ok_or(Error::Retired)?
            .seal_early(packet)
            .await??;
        body.get_mut(..packet.body().len())
            .ok_or(Error::Capacity)?
            .copy_from_slice(packet.body());
        Ok(())
    }
    pub(super) async fn tls_open_early(
        &mut self,
        pn: u64,
        header: &[u8],
        body: &mut [u8],
    ) -> Result<(usize, tls_owner::EarlyOpenReceipt), Error> {
        let packet = Packet::new(pn, header, body)?;
        let opened = self
            .tls
            .as_mut()
            .ok_or(Error::Retired)?
            .open_early(packet)
            .await??;
        let len = opened.packet.body().len();
        body.get_mut(..len)
            .ok_or(Error::Capacity)?
            .copy_from_slice(opened.packet.body());
        Ok((len, opened.receipt))
    }
}
