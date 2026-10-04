//! Affine transitions between the projected prefix, ordinary application and
//! closing continuations. Payload numbers correlate owned slots only.
use super::{Error, OrdinaryRetired, Roles, keys, protocol as p, termination};
use crate::connection::{
    Config, ReceiveContinuation, ReceiveMaterial, Side, TransmitContinuation,
    parameters::{self, ValidatedPeer},
    tls::{Inbox, Transcript},
};
use core::pin::pin;

pub(crate) struct Received<'scope, const P: usize> {
    pub material: ReceiveMaterial<'scope>,
    pub peer: ValidatedPeer<'scope, P>,
}
fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
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
    let sequence = scope.connection_generation();
    let (material, finished) = received.into_parts();
    let write_slot = Inbox::new();
    let validation_slot = Inbox::new();
    let finished_slot = Inbox::new();
    let transcript_slot = Inbox::new();
    let admission_slot = Inbox::new();
    let mut material_out = None;
    let mut peer_out = None;
    let mut write_out = None;
    let mut transcript_out = None;
    {
        let mut from_tx = pin!(async {
            write_slot.put(transmitted).map_err(|_| Error::Binding)?;
            roles.handshake.tx.send::<p::WriteStart>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut write = pin!(async {
            check(roles.tx_keys.recv::<p::WriteStart>().await?, sequence)?;
            let transmitted = write_slot.take().map_err(|_| Error::Binding)?;
            validation_slot
                .put(transmitted)
                .map_err(|_| Error::Binding)?;
            roles
                .tx_keys
                .send::<p::WriteForAdmission>(&sequence)
                .await?;
            // ReadAdmission cannot be sent until RX consumed the write token.
            check(roles.tx_keys.recv::<p::ReadAdmission>().await?, sequence)?;
            let (transmitted, peer) = admission_slot.take().map_err(|_| Error::Binding)?;
            write_out = Some(transmitted);
            peer_out = Some(peer);
            Ok::<(), Error>(())
        });
        let mut from_rx = pin!(async {
            check(
                roles.handshake.rx.recv::<p::WriteForAdmission>().await?,
                sequence,
            )?;
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
                None,
            )?;
            finished_slot
                .put((Received { material, peer }, transmitted))
                .map_err(|_| Error::Binding)?;
            roles
                .handshake
                .rx
                .send::<p::FinishedValidated>(&sequence)
                .await?;
            Ok::<(), Error>(())
        });
        let mut from_tls = pin!(async {
            check(
                roles
                    .handshake
                    .tls_rx
                    .recv::<p::FinishedValidated>()
                    .await?,
                sequence,
            )?;
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
                .send::<p::TranscriptStart>(&sequence)
                .await?;
            Ok::<(), Error>(())
        });
        let mut receive = pin!(async {
            check(roles.receive.recv::<p::TranscriptStart>().await?, sequence)?;
            let (received, transmitted, transcript) =
                transcript_slot.take().map_err(|_| Error::Binding)?;
            material_out = Some(received.material);
            transcript_out = Some(transcript);
            admission_slot
                .put((transmitted, received.peer))
                .map_err(|_| Error::Binding)?;
            roles.receive.send::<p::ReadAdmission>(&sequence).await?;
            Ok::<(), Error>(())
        });
        crate::runtime::TaskSet::new([
            from_tx.as_mut(),
            write.as_mut(),
            from_rx.as_mut(),
            from_tls.as_mut(),
            receive.as_mut(),
        ])
        .await?;
    }
    Ok((
        Received {
            material: material_out.ok_or(Error::Binding)?,
            peer: peer_out.ok_or(Error::Binding)?,
        },
        write_out.ok_or(Error::Binding)?,
        transcript_out.ok_or(Error::Binding)?,
    ))
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
    let sequence = peer.scope().connection_generation();
    let control_slot = Inbox::new();
    let owner_slot = Inbox::new();
    let peer_slot = Inbox::new();
    let mut peer_out = None;
    let mut owner_out = None;
    let mut control_out = None;
    {
        let mut send_owner = pin!(async {
            control_slot
                .put(keys::RxControl::new(exchange))
                .map_err(|_| Error::Binding)?;
            roles
                .tx_keys
                .send::<p::KeyControlAdmission>(&sequence)
                .await?;
            owner_slot.put((owner, peer)).map_err(|_| Error::Binding)?;
            roles.tx_keys.send::<p::WriteAdmission>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut admit_control = pin!(async {
            check(
                roles.rx_keys.recv::<p::KeyControlAdmission>().await?,
                sequence,
            )?;
            control_out = Some(control_slot.take().map_err(|_| Error::Binding)?);
            Ok::<(), Error>(())
        });
        let mut admit_transmit = pin!(async {
            check(roles.transmit.recv::<p::WriteAdmission>().await?, sequence)?;
            let (writer, peer) = owner_slot.take().map_err(|_| Error::Binding)?;
            owner_out = Some(writer);
            peer_slot.put(peer).map_err(|_| Error::Binding)?;
            roles.transmit.send::<p::StreamAdmission>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut admit_source = pin!(async {
            check(roles.source.recv::<p::StreamAdmission>().await?, sequence)?;
            peer_out = Some(peer_slot.take().map_err(|_| Error::Binding)?);
            Ok::<(), Error>(())
        });
        crate::runtime::TaskSet::new([
            send_owner.as_mut(),
            admit_control.as_mut(),
            admit_transmit.as_mut(),
            admit_source.as_mut(),
        ])
        .await?;
    }
    Ok((
        peer_out.ok_or(Error::Binding)?,
        owner_out.ok_or(Error::Binding)?,
        control_out.ok_or(Error::Binding)?,
    ))
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
    let sequence = scope.connection_generation();
    let (peer, files) = outcomes.into_parts();
    let publication_slot = Inbox::new();
    let key_grant = Inbox::new();
    let key_result = Inbox::new();
    let peer_grant = Inbox::new();
    let peer_result = Inbox::new();
    let files_grant = Inbox::new();
    let files_result = Inbox::new();
    let close_slot = Inbox::new();
    let mut received = None;
    {
        let mut publication = pin!(async {
            publication_slot.put(ordinary).map_err(|_| Error::Binding)?;
            roles
                .transmit
                .send::<p::PublicationRetired>(&sequence)
                .await?;
            check(roles.transmit.recv::<p::CloseAuthority>().await?, sequence)?;
            received = Some(close_slot.take().map_err(|_| Error::Binding)?);
            Ok::<(), Error>(())
        });
        let mut key_owner = pin!(async {
            check(
                roles.rx_keys.recv::<p::KeyRetirementGrant>().await?,
                sequence,
            )?;
            let ordinary = key_grant.take().map_err(|_| Error::Binding)?;
            key_result.put(ordinary).map_err(|_| Error::Binding)?;
            roles.rx_keys.send::<p::KeyRetirement>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut peer_owner = pin!(async {
            check(
                roles.peer_close.recv::<p::PeerRetirementGrant>().await?,
                sequence,
            )?;
            let ordinary = peer_grant.take().map_err(|_| Error::Binding)?;
            peer_result
                .put(RetiredPeer { ordinary, peer })
                .map_err(|_| Error::Binding)?;
            roles.peer_close.send::<p::PeerOutcome>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut files_owner = pin!(async {
            check(
                roles.files_close.recv::<p::FilesRetirementGrant>().await?,
                sequence,
            )?;
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
            roles.files_close.send::<p::FilesOutcome>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut join = pin!(async {
            check(
                roles.close_join.recv::<p::PublicationRetired>().await?,
                sequence,
            )?;
            key_grant
                .put(publication_slot.take().map_err(|_| Error::Binding)?)
                .map_err(|_| Error::Binding)?;
            roles
                .close_join
                .send::<p::KeyRetirementGrant>(&sequence)
                .await?;
            check(roles.close_join.recv::<p::KeyRetirement>().await?, sequence)?;
            peer_grant
                .put(key_result.take().map_err(|_| Error::Binding)?)
                .map_err(|_| Error::Binding)?;
            roles
                .close_join
                .send::<p::PeerRetirementGrant>(&sequence)
                .await?;
            check(roles.close_join.recv::<p::PeerOutcome>().await?, sequence)?;
            files_grant
                .put(peer_result.take().map_err(|_| Error::Binding)?)
                .map_err(|_| Error::Binding)?;
            roles
                .close_join
                .send::<p::FilesRetirementGrant>(&sequence)
                .await?;
            check(roles.close_join.recv::<p::FilesOutcome>().await?, sequence)?;
            close_slot
                .put(files_result.take().map_err(|_| Error::Binding)?)
                .map_err(|_| Error::Binding)?;
            roles
                .close_join
                .send::<p::CloseAuthority>(&sequence)
                .await?;
            Ok::<(), Error>(())
        });
        crate::runtime::TaskSet::new([
            publication.as_mut(),
            key_owner.as_mut(),
            peer_owner.as_mut(),
            files_owner.as_mut(),
            join.as_mut(),
        ])
        .await?;
    }
    received.ok_or(Error::Binding)
}
