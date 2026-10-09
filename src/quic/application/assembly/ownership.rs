//! Affine transitions between the projected prefix, ordinary application and
//! closing continuations. Hibana owns progress; actual affine slots own resources.
use super::super::{Error, OrdinaryRetired, Roles, global as p, keys, termination};
use crate::quic::{
    Config, ReceiveContinuation, ReceiveMaterial, Side, TransmitContinuation,
    parameters::{self, ValidatedPeer},
    tls::{Inbox, Transcript},
};

pub(crate) struct Received<'scope, const P: usize> {
    pub material: ReceiveMaterial<'scope>,
    pub peer: ValidatedPeer<'scope, P>,
}

/// The settled write continuation visits prefix RX for Finished/TP/scope
/// validation, then returns through the actual transcript and read admission.
/// Its ownership gates every send in that round trip, including with Q=1.
pub(crate) async fn transfer<'source, 'scope, 'cfg, 'buf, const P: usize>(
    roles: &mut Roles<'_>,
    source: &'source mut Transcript<'scope, 'cfg, 'buf>,
    config: Config<'_>,
    received: ReceiveContinuation<'scope, P>,
    transmitted: TransmitContinuation<'scope>,
) -> Result<
    (
        Received<'scope, P>,
        TransmitContinuation<'scope>,
        &'source mut Transcript<'scope, 'cfg, 'buf>,
    ),
    Error,
> {
    let scope = source.scope();
    let (material, finished) = received.into_parts();
    let write_slot = Inbox::new();
    let validation_slot = Inbox::new();
    let finished_slot = Inbox::new();
    let transcript_slot = Inbox::new();
    let admission_slot = Inbox::new();
    let (_, (transmitted, peer), _, _, (material, transcript)) = {
        let from_tx = async {
            write_slot.put(transmitted).map_err(|_| Error::Binding)?;
            roles.handshake.tx.send::<p::WriteStart>(&()).await?;
            Ok::<(), Error>(())
        };
        let write = async {
            roles.tx_keys.recv::<p::WriteStart>().await?;
            let transmitted = write_slot.take().map_err(|_| Error::Binding)?;
            validation_slot
                .put(transmitted)
                .map_err(|_| Error::Binding)?;
            roles.tx_keys.send::<p::WriteForAdmission>(&()).await?;
            // ReadAdmission cannot be sent until RX consumed the write token.
            roles.tx_keys.recv::<p::ReadAdmission>().await?;
            let (transmitted, peer) = admission_slot.take().map_err(|_| Error::Binding)?;
            Ok::<_, Error>((transmitted, peer))
        };
        let from_rx = async {
            roles.handshake.rx.recv::<p::WriteForAdmission>().await?;
            let transmitted: TransmitContinuation<'scope> =
                validation_slot.take().map_err(|_| Error::Binding)?;
            if !core::ptr::eq(scope, transmitted.application.scope())
                || !core::ptr::eq(scope, transmitted.handshake.scope())
            {
                return Err(Error::Binding);
            }
            let peer = parameters::validate(
                finished,
                scope,
                config.side,
                material.peer_connection_id(),
                if config.side == Side::Client {
                    Some(config.original_destination_id)
                } else {
                    None
                },
                if config.side == Side::Client {
                    material.retry_source_id()
                } else {
                    None
                },
            )?;
            finished_slot
                .put((Received { material, peer }, transmitted))
                .map_err(|_| Error::Binding)?;
            roles.handshake.rx.send::<p::FinishedValidated>(&()).await?;
            Ok::<(), Error>(())
        };
        let from_tls = async {
            roles
                .handshake
                .tls_rx
                .recv::<p::FinishedValidated>()
                .await?;
            let (received, transmitted): (Received<'scope, P>, _) =
                finished_slot.take().map_err(|_| Error::Binding)?;
            if !core::ptr::eq(received.peer.scope(), source.scope()) {
                return Err(Error::Binding);
            }
            transcript_slot
                .put((received, transmitted, source))
                .map_err(|_| Error::Binding)?;
            roles
                .handshake
                .tls_rx
                .send::<p::TranscriptStart>(&())
                .await?;
            Ok::<(), Error>(())
        };
        let receive = async {
            roles.receive.recv::<p::TranscriptStart>().await?;
            let (received, transmitted, transcript) =
                transcript_slot.take().map_err(|_| Error::Binding)?;
            let material = received.material;
            admission_slot
                .put((transmitted, received.peer))
                .map_err(|_| Error::Binding)?;
            roles.receive.send::<p::ReadAdmission>(&()).await?;
            Ok::<_, Error>((material, transcript))
        };
        crate::runtime::join::values5(from_tx, write, from_rx, from_tls, receive).await?
    };
    Ok((Received { material, peer }, transmitted, transcript))
}

/// The actual write owner grants RX its unique control client before RX may
/// request key transitions; ordinary TX receives the owner's sealing access.
pub(crate) async fn admit<'lane, 'owner, 'scope, const P: usize>(
    roles: &mut Roles<'_>,
    peer: ValidatedPeer<'scope, P>,
    owner: &'owner keys::KeyOwner<'scope>,
    exchange: &'lane keys::Exchange<'owner, 'scope>,
) -> Result<
    (
        ValidatedPeer<'scope, P>,
        &'owner keys::KeyOwner<'scope>,
        keys::RxControl<'lane, 'owner, 'scope>,
    ),
    Error,
> {
    if !core::ptr::eq(peer.scope(), owner.scope()) {
        return Err(Error::Binding);
    }
    let control_slot = Inbox::new();
    let owner_slot = Inbox::new();
    let peer_slot = Inbox::new();
    let (_, control, writer, peer) = {
        let send_owner = async {
            control_slot
                .put(keys::RxControl::new(exchange))
                .map_err(|_| Error::Binding)?;
            roles.tx_keys.send::<p::KeyControlAdmission>(&()).await?;
            owner_slot.put((owner, peer)).map_err(|_| Error::Binding)?;
            roles.tx_keys.send::<p::WriteAdmission>(&()).await?;
            Ok::<(), Error>(())
        };
        let admit_control = async {
            roles.rx_keys.recv::<p::KeyControlAdmission>().await?;
            control_slot.take().map_err(|_| Error::Binding)
        };
        let admit_transmit = async {
            roles.transmit.recv::<p::WriteAdmission>().await?;
            let (writer, peer) = owner_slot.take().map_err(|_| Error::Binding)?;
            peer_slot.put(peer).map_err(|_| Error::Binding)?;
            roles.transmit.send::<p::StreamAdmission>(&()).await?;
            Ok::<_, Error>(writer)
        };
        let admit_source = async {
            roles.source.recv::<p::StreamAdmission>().await?;
            peer_slot.take().map_err(|_| Error::Binding)
        };
        crate::runtime::join::values4(send_owner, admit_control, admit_transmit, admit_source).await?
    };
    Ok((peer, writer, control))
}

pub(crate) struct Closing<'scope> {
    pub ordinary: OrdinaryRetired<'scope>,
    pub permission: termination::Permission<'scope>,
}
struct RetiredPeer<'scope> {
    ordinary: OrdinaryRetired<'scope>,
    peer: Option<termination::Permission<'scope>>,
}

/// This finite owner starts only after every ordinary future has completed.
/// The accumulated affine grant enables one retired owner's response at a time,
/// so each direct recv has one possible incoming sender even on a Q=1 carrier.
pub(crate) async fn retire<'scope>(
    roles: &mut Roles<'_>,
    ordinary: OrdinaryRetired<'scope>,
    outcomes: termination::TerminalOutcomes<'scope>,
) -> Result<Closing<'scope>, Error> {
    let scope = ordinary.scope();
    let (peer, files) = outcomes.into_parts();
    let publication_slot = Inbox::new();
    let key_grant = Inbox::new();
    let key_result = Inbox::new();
    let peer_grant = Inbox::new();
    let peer_result = Inbox::new();
    let files_grant = Inbox::new();
    let files_result = Inbox::new();
    let close_slot = Inbox::new();
    let (closing, _, _, _, _) = {
        let publication = async {
            publication_slot.put(ordinary).map_err(|_| Error::Binding)?;
            roles.transmit.send::<p::PublicationRetired>(&()).await?;
            roles.transmit.recv::<p::CloseAuthority>().await?;
            close_slot.take().map_err(|_| Error::Binding)
        };
        let key_owner = async {
            roles.rx_keys.recv::<p::KeyRetirementGrant>().await?;
            let ordinary = key_grant.take().map_err(|_| Error::Binding)?;
            key_result.put(ordinary).map_err(|_| Error::Binding)?;
            roles.rx_keys.send::<p::KeyRetirement>(&()).await?;
            Ok::<(), Error>(())
        };
        let peer_owner = async {
            roles.peer_close.recv::<p::PeerRetirementGrant>().await?;
            let ordinary = peer_grant.take().map_err(|_| Error::Binding)?;
            peer_result
                .put(RetiredPeer { ordinary, peer })
                .map_err(|_| Error::Binding)?;
            roles.peer_close.send::<p::PeerOutcome>(&()).await?;
            Ok::<(), Error>(())
        };
        let files_owner = async {
            roles.files_close.recv::<p::FilesRetirementGrant>().await?;
            let retired: RetiredPeer<'scope> = files_grant.take().map_err(|_| Error::Binding)?;
            for permission in [retired.peer.as_ref(), files.as_ref()]
                .into_iter()
                .flatten()
            {
                if !core::ptr::eq(scope, permission.scope()) {
                    return Err(Error::Binding);
                }
            }
            let permission = retired.peer.or(files).ok_or(Error::Binding)?;
            files_result
                .put(Closing {
                    ordinary: retired.ordinary,
                    permission,
                })
                .map_err(|_| Error::Binding)?;
            roles.files_close.send::<p::FilesOutcome>(&()).await?;
            Ok::<(), Error>(())
        };
        let join = async {
            roles.close_join.recv::<p::PublicationRetired>().await?;
            key_grant
                .put(publication_slot.take().map_err(|_| Error::Binding)?)
                .map_err(|_| Error::Binding)?;
            roles.close_join.send::<p::KeyRetirementGrant>(&()).await?;
            roles.close_join.recv::<p::KeyRetirement>().await?;
            peer_grant
                .put(key_result.take().map_err(|_| Error::Binding)?)
                .map_err(|_| Error::Binding)?;
            roles.close_join.send::<p::PeerRetirementGrant>(&()).await?;
            roles.close_join.recv::<p::PeerOutcome>().await?;
            files_grant
                .put(peer_result.take().map_err(|_| Error::Binding)?)
                .map_err(|_| Error::Binding)?;
            roles
                .close_join
                .send::<p::FilesRetirementGrant>(&())
                .await?;
            roles.close_join.recv::<p::FilesOutcome>().await?;
            close_slot
                .put(files_result.take().map_err(|_| Error::Binding)?)
                .map_err(|_| Error::Binding)?;
            roles.close_join.send::<p::CloseAuthority>(&()).await?;
            Ok::<(), Error>(())
        };
        crate::runtime::join::values5(publication, key_owner, peer_owner, files_owner, join).await?
    };
    Ok(closing)
}
