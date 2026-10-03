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
    let receive_slot = Inbox::new();
    let write_slot = Inbox::new();
    let transcript_slot = Inbox::new();
    let mut receive_out = None;
    let mut write_out = None;
    let mut transcript_out = None;
    {
        let mut send_receive = pin!(async {
            receive_slot.put(Received { material, peer }).map_err(|_| Error::Binding)?;
            roles.handshake.rx.send::<p::ReceiveStart>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut send_transcript = pin!(async {
            transcript_slot.put(source).map_err(|_| Error::Binding)?;
            roles.handshake.tls_rx.send::<p::TranscriptStart>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut send_write = pin!(async {
            write_slot.put(transmitted).map_err(|_| Error::Binding)?;
            roles.handshake.tx.send::<p::WriteStart>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut receive = pin!(async {
            check(roles.receive.recv::<p::ReceiveStart>().await?, sequence)?;
            receive_out = Some(receive_slot.take().map_err(|_| Error::Binding)?);
            check(roles.receive.recv::<p::TranscriptStart>().await?, sequence)?;
            transcript_out = Some(transcript_slot.take().map_err(|_| Error::Binding)?);
            Ok::<(), Error>(())
        });
        let mut write = pin!(async {
            check(roles.tx_keys.recv::<p::WriteStart>().await?, sequence)?;
            write_out = Some(write_slot.take().map_err(|_| Error::Binding)?);
            Ok::<(), Error>(())
        });
        crate::runtime::TaskSet::new([send_receive.as_mut(), send_transcript.as_mut(), send_write.as_mut(), receive.as_mut(), write.as_mut()]).await?;
    }
    Ok((receive_out.ok_or(Error::Binding)?, write_out.ok_or(Error::Binding)?, transcript_out.ok_or(Error::Binding)?))
}

/// Source admission carries the actual validated Finished object. The writer
/// receives a reference to the unique installed write owner after TX_KEYS has
/// taken the prefix's actual key material. Neither is a copied ready flag.
pub(crate) async fn admit<'owner, 'scope, const P: usize>(
    roles: &mut Roles<'_>, peer: ValidatedPeer<'scope, P>, owner: &'owner keys::KeyOwner<'scope>,
) -> Result<(ValidatedPeer<'scope, P>, &'owner keys::KeyOwner<'scope>), Error> {
    if !core::ptr::eq(peer.scope(), owner.scope()) { return Err(Error::Binding); }
    let sequence = peer.scope().connection_generation();
    let peer_slot = Inbox::new();
    let owner_slot = Inbox::new();
    let mut peer_out = None;
    let mut owner_out = None;
    {
        let mut send_peer = pin!(async {
            peer_slot.put(peer).map_err(|_| Error::Binding)?;
            roles.receive.send::<p::StreamAdmission>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut receive_peer = pin!(async {
            check(roles.source.recv::<p::StreamAdmission>().await?, sequence)?;
            peer_out = Some(peer_slot.take().map_err(|_| Error::Binding)?);
            Ok::<(), Error>(())
        });
        let mut send_owner = pin!(async {
            owner_slot.put(owner).map_err(|_| Error::Binding)?;
            roles.tx_keys.send::<p::WriteAdmission>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut receive_owner = pin!(async {
            check(roles.transmit.recv::<p::WriteAdmission>().await?, sequence)?;
            owner_out = Some(owner_slot.take().map_err(|_| Error::Binding)?);
            Ok::<(), Error>(())
        });
        crate::runtime::TaskSet::new([send_peer.as_mut(), receive_peer.as_mut(), send_owner.as_mut(), receive_owner.as_mut()]).await?;
    }
    Ok((peer_out.ok_or(Error::Binding)?, owner_out.ok_or(Error::Binding)?))
}

pub(crate) struct Closing<'owner, 'scope> {
    pub ordinary: OrdinaryRetired<'scope>,
    pub keys: keys::KeysQuiesced<'owner, 'scope>,
    pub permission: termination::Permission<'scope>,
}

/// Called only after the full ordinary TaskSet has completed. The TX role
/// receives the actual key-role retirement and actual terminal permission.
pub(crate) async fn retire<'owner, 'scope>(
    roles: &mut Roles<'_>, ordinary: OrdinaryRetired<'scope>,
    keys: keys::KeysQuiesced<'owner, 'scope>, permission: termination::Permission<'scope>,
) -> Result<Closing<'owner, 'scope>, Error> {
    if !core::ptr::eq(ordinary.scope(), permission.scope()) { return Err(Error::Binding); }
    let sequence = ordinary.scope().connection_generation();
    let key_slot = Inbox::new();
    let close_slot = Inbox::new();
    let mut received_keys = None;
    let mut received_close = None;
    {
        let mut send_keys = pin!(async {
            key_slot.put(keys).map_err(|_| Error::Binding)?;
            roles.rx_keys.send::<p::KeyRetirement>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut send_close = pin!(async {
            close_slot.put(permission).map_err(|_| Error::Binding)?;
            roles.peer_close.send::<p::CloseAuthority>(&sequence).await?;
            Ok::<(), Error>(())
        });
        let mut receive = pin!(async {
            check(roles.transmit.recv::<p::KeyRetirement>().await?, sequence)?;
            received_keys = Some(key_slot.take().map_err(|_| Error::Binding)?);
            check(roles.transmit.recv::<p::CloseAuthority>().await?, sequence)?;
            received_close = Some(close_slot.take().map_err(|_| Error::Binding)?);
            Ok::<(), Error>(())
        });
        crate::runtime::TaskSet::new([send_keys.as_mut(), send_close.as_mut(), receive.as_mut()]).await?;
    }
    Ok(Closing { ordinary, keys: received_keys.ok_or(Error::Binding)?, permission: received_close.ok_or(Error::Binding)? })
}
