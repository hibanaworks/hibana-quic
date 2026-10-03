//! Affine domain permissions derived from one actual TLS Finished transition.
//!
//! The packet role validates the exact owner-bound transport parameters and
//! connection IDs, then splits one receipt into distinct application, path and
//! early-release permissions. Observations cannot be converted back to grants.
//! This does not assert that client TLS completion is QUIC confirmation.

use super::tls_owner::FinishedReceipt;
use crate::{
    early_data::EarlyStatus,
    early_send::Decision,
    parameters::{self, Parameters, Peer},
    streams::Limits,
};

pub const PARAMETER_CAPACITY: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnboundParameters,
    Capacity,
    UnresolvedEarlyDecision,
    Parameters(parameters::Error),
}
impl From<parameters::Error> for Error {
    fn from(value: parameters::Error) -> Self {
        Self::Parameters(value)
    }
}

/// Only the authenticated packet role can construct these domain permissions.
/// Their distinct types prevent a path permission from opening stream access.
pub struct ReadyGrants {
    pub application: AppReady,
    pub path: PathReady,
    pub early: EarlyReady,
}

/// One-time permission to install the actual peer's stream limits.
/// ```compile_fail
/// use hibana_quic::roles::connection_authority::AppReady;
/// fn duplicate(grant: AppReady) { let first = grant; let second = grant; }
/// ```
pub struct AppReady {
    generation: u64,
    limits: Limits,
    early: Option<Decision>,
}
impl AppReady {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn limits(&self) -> Limits {
        self.limits
    }
    pub const fn early_decision(&self) -> Option<Decision> {
        self.early
    }
}

/// Parameter permission for the path owner. Initial address learning is a
/// separate operation; this grant never authenticates an arbitrary tuple.
pub struct PathReady {
    generation: u64,
    peer: Peer,
    parameters: [u8; PARAMETER_CAPACITY],
    parameters_len: usize,
    peer_initial: [u8; 20],
    peer_initial_len: usize,
}
impl PathReady {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn peer_role(&self) -> Peer {
        self.peer
    }
    pub fn peer_initial_cid(&self) -> &[u8] {
        &self.peer_initial[..self.peer_initial_len]
    }
    pub fn peer_parameters(&self) -> Result<Parameters<'_>, parameters::Error> {
        Parameters::parse(
            &self.parameters[..self.parameters_len],
            self.peer,
            &mut [0; 64],
        )
    }
    /// Only a server's received client Finished confirms its QUIC handshake.
    /// A client still requires an authenticated HANDSHAKE_DONE frame.
    pub const fn server_handshake_confirmed(&self) -> bool {
        matches!(self.peer, Peer::Client)
    }
}

/// Finished-derived early-data decision. Replay/quarantine ownership is still
/// independently required before releasing any early bytes.
pub struct EarlyReady {
    generation: u64,
    peer: Peer,
    limits: Limits,
    decision: Option<Decision>,
}
impl EarlyReady {
    pub const fn peer_role(&self) -> Peer {
        self.peer
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn limits(&self) -> Limits {
        self.limits
    }
    pub const fn decision(&self) -> Option<Decision> {
        self.decision
    }
}

/// Called by the packet role only, using its actual connection identity.
/// No caller-supplied ready flag, replacement limits or unbound parameter
/// snapshot crosses into a data owner. All validation precedes grant creation.
pub(crate) fn verify_and_split(
    receipt: FinishedReceipt,
    raw: &[u8],
    peer: Peer,
    peer_initial: &[u8],
    original_destination: Option<&[u8]>,
    retry_source: Option<&[u8]>,
) -> Result<ReadyGrants, Error> {
    if raw.len() > PARAMETER_CAPACITY || peer_initial.len() > 20 {
        return Err(Error::Capacity);
    }
    if !receipt.authenticates_peer_parameters(raw) {
        return Err(Error::UnboundParameters);
    }
    let parameters = Parameters::parse(raw, peer, &mut [0; 64])?;
    parameters.verify_connection_ids(peer_initial, original_destination, retry_source)?;
    let limits = Limits {
        max_data: parameters.get_integer(4, 0)?,
        stream_data_bidi_local: parameters.get_integer(5, 0)?,
        stream_data_bidi_remote: parameters.get_integer(6, 0)?,
        stream_data_uni: parameters.get_integer(7, 0)?,
        max_streams_bidi: parameters.get_integer(8, 0)?,
        max_streams_uni: parameters.get_integer(9, 0)?,
    };
    let decision = match receipt.early_status() {
        EarlyStatus::Accepted => Some(Decision::Accepted),
        EarlyStatus::Rejected => Some(Decision::Rejected),
        EarlyStatus::Disabled => None,
        EarlyStatus::Offered | EarlyStatus::AcceptedPendingFinished => {
            return Err(Error::UnresolvedEarlyDecision);
        }
    };
    let generation = receipt.generation();
    let mut stored = [0; PARAMETER_CAPACITY];
    stored[..raw.len()].copy_from_slice(raw);
    let mut cid = [0; 20];
    cid[..peer_initial.len()].copy_from_slice(peer_initial);
    Ok(ReadyGrants {
        application: AppReady {
            generation,
            limits,
            early: decision,
        },
        path: PathReady {
            generation,
            peer,
            parameters: stored,
            parameters_len: raw.len(),
            peer_initial: cid,
            peer_initial_len: peer_initial.len(),
        },
        early: EarlyReady {
            generation,
            peer,
            limits,
            decision,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const CLIENT: &[u8] = &[
        15, 8, b'c', b'l', b'i', b'e', b'n', b't', b'i', b'd', 4, 1, 42,
    ];
    fn receipt() -> FinishedReceipt {
        crate::test_evidence::finished_with_parameters(911, CLIENT)
    }
    #[test]
    fn actual_finished_binds_parameters_and_splits_distinct_permissions() {
        let receipt = receipt();
        assert!(receipt.authenticates_peer_parameters(CLIENT));
        assert!(!receipt.authenticates_peer_parameters(&CLIENT[..CLIENT.len() - 1]));
        let grants =
            verify_and_split(receipt, CLIENT, Peer::Client, b"clientid", None, None).unwrap();
        assert_eq!(grants.application.generation(), 911);
        assert_eq!(grants.application.limits().max_data, 42);
        assert_eq!(grants.application.early_decision(), None);
        assert_eq!(grants.path.peer_initial_cid(), b"clientid");
        assert_eq!(
            grants.path.peer_parameters().unwrap().get_integer(4, 0),
            Ok(42)
        );
        assert!(grants.path.server_handshake_confirmed());
        assert_eq!(grants.early.generation(), 911);
        assert_eq!(grants.early.decision(), None);
    }
    #[test]
    fn substituted_parameter_bytes_cannot_mint_ready_grants() {
        let mut changed = CLIENT.to_vec();
        *changed.last_mut().unwrap() = 43;
        assert!(matches!(
            verify_and_split(receipt(), &changed, Peer::Client, b"clientid", None, None),
            Err(Error::UnboundParameters)
        ));
    }
    #[test]
    fn wrong_connection_identity_cannot_mint_ready_grants() {
        assert!(matches!(
            verify_and_split(receipt(), CLIENT, Peer::Client, b"wrongcid", None, None),
            Err(Error::Parameters(parameters::Error::ConnectionIdMismatch))
        ));
    }
}
