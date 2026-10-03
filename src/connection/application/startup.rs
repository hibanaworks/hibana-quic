//! Affine transitions between the projected prefix, ordinary application and
//! closing continuations. Payload numbers correlate owned slots only.
use super::{Error, OrdinaryRetired, Roles, keys, protocol as p, termination};
use crate::connection::{Config, ReceiveContinuation, ReceiveMaterial, Side, TransmitContinuation,
    parameters::{self, ValidatedPeer}, tls::{Inbox, Transcript}};
use core::pin::pin;

pub(crate) struct Received<'scope, const P: usize> {
    pub material: ReceiveMaterial<'scope>,
    pub peer: ValidatedPeer<'scope, P>,
}

fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected { Ok(()) } else { Err(Error::Binding) }
}

/// The prefix RX validates the authenticated parameters before transferring
/// either application read authority or permission to create stream limits.
pub(crate) async fn transfer<'source, 'scope, 'cfg, 'buf, const P: usize>(
    roles: &mut Roles<'_>,
    source: &'source mut Transcript<'scope, 'cfg, 'buf>,
    config: Config<'_>,
    received: ReceiveContinuation<'scope, P>,
    transmitted: TransmitContinuation<'scope>,
) -> Result<(Received<'scope, P>, TransmitContinuation<'scope>, &'source mut Transcript<'scope, 'cfg, 'buf>), Error> {
    let scope = source.scope();
    let sequence = scope.connection_generation();
    let (material, finished) = received.into_parts();
    let peer = parameters::validate(finished, scope, config.side, material.peer_connection_id(),
        if config.side == Side::Client { Some(config.original_destination_id) } else { None }, None)?;
    let finished_slot = Inbox::new();
    let transcript_slot = Inbox::new();
    let peer_slot = Inbox::new();
    let write_slot = Inbox::new();
    let mut material_out = None;
    let mut peer_out = None;
    let mut write_out = None;
    let mut transcript_out = None;
    {
        let mut from_rx = pin!(async {
            finished_slot.put(Received { material, peer }).map_err(|_| Error::Binding)?;
            roles.handshake.rx.send::<p::FinishedValidated>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut from_tls = pin!(async {
            check(roles.handshake.tls_rx.recv::<p::FinishedValidated>().await?, sequence)?;
            let received = finished_slot.take().map_err(|_| Error::Binding)?;
            if !core::ptr::eq(received.peer.scope(), source.scope()) { return Err(Error::Binding); }
            transcript_slot.put((received, source)).map_err(|_| Error::Binding)?;
            roles.handshake.tls_rx.send::<p::TranscriptStart>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut receive = pin!(async {
            check(roles.receive.recv::<p::TranscriptStart>().await?, sequence)?;
            let (received, transcript) = transcript_slot.take().map_err(|_| Error::Binding)?;
            material_out = Some(received.material);
            transcript_out = Some(transcript);
            peer_slot.put(received.peer).map_err(|_| Error::Binding)?;
            roles.receive.send::<p::ReadAdmission>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut from_tx = pin!(async {
            check(roles.handshake.tx.recv::<p::ReadAdmission>().await?, sequence)?;
            let peer = peer_slot.take().map_err(|_| Error::Binding)?;
            if !core::ptr::eq(peer.scope(), transmitted.application.scope()) { return Err(Error::Binding); }
            write_slot.put((transmitted, peer)).map_err(|_| Error::Binding)?;
            roles.handshake.tx.send::<p::WriteStart>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut write = pin!(async {
            check(roles.tx_keys.recv::<p::WriteStart>().await?, sequence)?;
            let (write, peer) = write_slot.take().map_err(|_| Error::Binding)?;
            write_out = Some(write);
            peer_out = Some(peer);
            Ok::<(), Error>(())
        });
        crate::runtime::TaskSet::new([from_rx.as_mut(), from_tls.as_mut(), receive.as_mut(), from_tx.as_mut(), write.as_mut()]).await?;
    }
    Ok((Received { material: material_out.ok_or(Error::Binding)?, peer: peer_out.ok_or(Error::Binding)? },
        write_out.ok_or(Error::Binding)?, transcript_out.ok_or(Error::Binding)?))
}

/// The TX key facet constructs the actual owner, then transfers that owner's
/// borrowed sealing access alongside the validated Finished admission. TX
/// forwards the latter to the source that installs the peer's stream limits.
pub(crate) async fn admit<'owner, 'scope, const P: usize>(
    roles: &mut Roles<'_>, peer: ValidatedPeer<'scope, P>, owner: &'owner keys::KeyOwner<'scope>,
) -> Result<(ValidatedPeer<'scope, P>, &'owner keys::KeyOwner<'scope>), Error> {
    if !core::ptr::eq(peer.scope(), owner.scope()) { return Err(Error::Binding); }
    let sequence = peer.scope().connection_generation();
    let owner_slot = Inbox::new();
    let peer_slot = Inbox::new();
    let mut peer_out = None;
    let mut owner_out = None;
    {
        let mut send_owner = pin!(async {
            owner_slot.put((owner, peer)).map_err(|_| Error::Binding)?;
            roles.tx_keys.send::<p::WriteAdmission>(&sequence).await?;
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
        crate::runtime::TaskSet::new([send_owner.as_mut(), admit_transmit.as_mut(), admit_source.as_mut()]).await?;
    }
    Ok((peer_out.ok_or(Error::Binding)?, owner_out.ok_or(Error::Binding)?))
}

pub(crate) struct Closing<'owner, 'scope> {
    pub ordinary: OrdinaryRetired<'scope>,
    pub keys: keys::KeysQuiesced<'owner, 'scope>,
    pub permission: termination::Permission<'scope>,
}

/// Called only after the full ordinary TaskSet has completed. The TX role
/// receives the joined actual key-role retirement and terminal permission.
/// The terminal facet first receives the key grant, preserving causal knowledge.
pub(crate) async fn retire<'owner, 'scope>(
    roles: &mut Roles<'_>, ordinary: OrdinaryRetired<'scope>,
    keys: keys::KeysQuiesced<'owner, 'scope>, permission: termination::Permission<'scope>,
) -> Result<Closing<'owner, 'scope>, Error> {
    if !core::ptr::eq(ordinary.scope(), permission.scope()) { return Err(Error::Binding); }
    let sequence = ordinary.scope().connection_generation();
    let key_slot = Inbox::new();
    let close_slot = Inbox::new();
    let mut received = None;
    {
        let mut send_keys = pin!(async {
            key_slot.put(keys).map_err(|_| Error::Binding)?;
            roles.rx_keys.send::<p::KeyRetirement>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut send_close = pin!(async {
            check(roles.peer_close.recv::<p::KeyRetirement>().await?, sequence)?;
            let keys = key_slot.take().map_err(|_| Error::Binding)?;
            close_slot.put(Closing { ordinary, keys, permission }).map_err(|_| Error::Binding)?;
            roles.peer_close.send::<p::CloseAuthority>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut receive = pin!(async {
            check(roles.transmit.recv::<p::CloseAuthority>().await?, sequence)?;
            received = Some(close_slot.take().map_err(|_| Error::Binding)?);
            Ok::<(), Error>(())
        });
        crate::runtime::TaskSet::new([send_keys.as_mut(), send_close.as_mut(), receive.as_mut()]).await?;
    }
    received.ok_or(Error::Binding)
}
