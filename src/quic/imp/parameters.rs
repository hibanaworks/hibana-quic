//! Affine Finished-to-application parameter boundary.
use super::{
    Side,
    tls::{Finished, PeerParameters},
};
use crate::crypto::directional::ApplicationKeyScope;
use crate::quic::imp::kernel::parameters;
use crate::quic::imp::kernel::parameters::Parameters;
use crate::quic::imp::kernel::parameters::Peer;
use crate::quic::imp::kernel::streams::Limits;
use hibana_tls::handshake::keys::FinishedAuthenticated;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Binding,
    Parameters(parameters::Error),
}
impl From<parameters::Error> for Error {
    fn from(value: parameters::Error) -> Self {
        Self::Parameters(value)
    }
}
#[must_use]
pub struct ValidatedPeer<'scope, const P: usize> {
    finished: FinishedAuthenticated<'scope>,
    parameters: PeerParameters<P>,
    limits: Limits,
    max_udp_payload: u64,
    ack_delay_exponent: u8,
    max_ack_delay_us: u64,
    max_idle_timeout_ms: u64,
    active_connection_id_limit: u64,
}
impl<'scope, const P: usize> ValidatedPeer<'scope, P> {
    pub fn scope(&self) -> &'scope ApplicationKeyScope {
        self.finished.scope()
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }
    pub fn max_udp_payload(&self) -> u64 {
        self.max_udp_payload
    }
    pub fn ack_delay_exponent(&self) -> u8 {
        self.ack_delay_exponent
    }
    pub fn max_ack_delay_us(&self) -> u64 {
        self.max_ack_delay_us
    }
    pub fn max_idle_timeout_ms(&self) -> u64 {
        self.max_idle_timeout_ms
    }
    pub fn active_connection_id_limit(&self) -> u64 {
        self.active_connection_id_limit
    }
    pub fn parameters(&self) -> &[u8] {
        self.parameters.bytes()
    }
    pub(crate) fn finished(&self) -> &FinishedAuthenticated<'scope> {
        &self.finished
    }
    pub(crate) fn into_finished(self) -> FinishedAuthenticated<'scope> {
        self.finished
    }
}
pub fn validate<'scope, const P: usize>(
    finished: Finished<'scope, P>,
    expected_scope: &'scope ApplicationKeyScope,
    local_side: Side,
    peer_initial_cid: &[u8],
    original_destination: Option<&[u8]>,
    retry_source: Option<&[u8]>,
) -> Result<ValidatedPeer<'scope, P>, Error> {
    let (receipt, raw) = finished.into_parts();
    let expected_side = match local_side {
        Side::Client => hibana_tls::schedule::Side::Client,
        Side::Server => hibana_tls::schedule::Side::Server,
    };
    if !core::ptr::eq(receipt.scope(), expected_scope)
        || receipt.side() != expected_side
        || !receipt.authenticates_peer_parameters(raw.bytes())
    {
        return Err(Error::Binding);
    }
    let peer = match local_side {
        Side::Client => Peer::Server,
        Side::Server => Peer::Client,
    };
    let parameters = Parameters::parse(raw.bytes(), peer, &mut [0; 64])?;
    parameters.verify_connection_ids(peer_initial_cid, original_destination, retry_source)?;
    let limits = Limits {
        max_data: parameters.get_integer(4, 0)?,
        stream_data_bidi_local: parameters.get_integer(5, 0)?,
        stream_data_bidi_remote: parameters.get_integer(6, 0)?,
        stream_data_uni: parameters.get_integer(7, 0)?,
        max_streams_bidi: parameters.get_integer(8, 0)?,
        max_streams_uni: parameters.get_integer(9, 0)?,
    };
    let max_udp_payload = parameters.get_integer(3, 65527)?;
    let ack_delay_exponent = parameters.get_integer(10, 3)? as u8;
    let max_ack_delay_us = parameters
        .get_integer(11, 25)?
        .checked_mul(1000)
        .ok_or(Error::Binding)?;
    let max_idle_timeout_ms = parameters.get_integer(1, 0)?;
    let active_connection_id_limit = parameters.get_integer(14, 2)?;
    Ok(ValidatedPeer {
        finished: receipt,
        parameters: raw,
        limits,
        max_udp_payload,
        ack_delay_exponent,
        max_ack_delay_us,
        max_idle_timeout_ms,
        active_connection_id_limit,
    })
}

/// Local transport parameter advertisement.
pub mod advertisement;
