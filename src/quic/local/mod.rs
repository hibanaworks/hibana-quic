//! Direct receive, transmit and physical-publication role continuations.
use super::global as p;
use super::wire::{PlainPacket, WriteKeys};
use super::*;
use crate::{
    crypto::directional::ApplicationKeyScope,
    quic::kernel::packet::{self, Frame, FrameIter, Header, LongType, PacketIter, ParseLimits},
    quic::kernel::parameters::{Parameters, Peer},
};
use core::{future::Future, pin::pin};
use hibana::g::Message;

mod publication;
mod receive;
mod sealing;
mod transmit;
pub(super) use publication::publish;
pub(super) use receive::receive;
pub(super) use sealing::prepare;
use sealing::{RecoveryPacket, prepare_recovery_packet};
pub(super) use transmit::transmit;

#[allow(clippy::too_many_arguments)]
pub async fn handshake<'scope, 'book, const N: usize, const P: usize>(
    roles: &mut Roles<'_>,
    source: &mut Transcript<'scope, '_, '_>,
    config: Config<'_>,
    reassembly: [CryptoBuffer<'_>; 2],
    receive_io: &mut impl DatagramRx,
    send_io: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut publication_gate::Issuer<'_, 'scope>,
    storage: &mut Storage<'scope, 'book, N, P>,
    book: &'book mut recovery::Recovery<'scope, N>,
    adapter_outcome: &Outcome,
) -> Result<(ReceiveContinuation<'scope, P>, TransmitContinuation<'scope>), Error> {
    handshake_with_early(
        roles,
        source,
        config,
        reassembly,
        receive_io,
        send_io,
        clock,
        issuer,
        storage,
        book,
        adapter_outcome,
        None,
    )
    .await
    .map(|(read, write, _pending)| (read, write))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handshake_with_early<'scope, 'book, const N: usize, const P: usize>(
    roles: &mut Roles<'_>,
    source: &mut Transcript<'scope, '_, '_>,
    config: Config<'_>,
    reassembly: [CryptoBuffer<'_>; 2],
    receive_io: &mut impl DatagramRx,
    send_io: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut publication_gate::Issuer<'_, 'scope>,
    storage: &mut Storage<'scope, 'book, N, P>,
    book: &'book mut recovery::Recovery<'scope, N>,
    adapter_outcome: &Outcome,
    early: Option<&mut early_client::Requests<'_, 'scope>>,
) -> Result<
    (
        ReceiveContinuation<'scope, P>,
        TransmitContinuation<'scope>,
        Option<([u8; N], ReceivedDatagram, u64)>,
    ),
    Error,
> {
    let storage = &*storage;
    config.validate()?;
    if N < 1200
        || book.max_datagram_size() > N as u64
        || !core::ptr::eq(source.scope(), book.scope())
        || config.side != book.side()
        || storage.peer.borrow().bytes() != config.peer_connection_id
    {
        return Err(Error::Binding);
    }
    let expected_side = match config.side {
        Side::Client => crate::tls::schedule::Side::Client,
        Side::Server => crate::tls::schedule::Side::Server,
    };
    if source.side() != expected_side || source.version() != config.version {
        return Err(Error::Binding);
    }
    let _clear = Clear(storage);
    let scope = source.scope();
    let mut integrity = source.take_integrity_budget()?;
    let initial = crypto::initial_keys(
        config
            .retry_source_id
            .unwrap_or(config.original_destination_id),
    )?;
    let (read, write) = match config.side {
        Side::Client => (initial.server, initial.client),
        Side::Server => (initial.client, initial.server),
    };
    let initial = initial::Keys::new(scope, read, write)?;
    if config.version != crate::quic::kernel::version::Version::V1 {
        let pair = crypto::initial_keys_for_version(
            config.version,
            config
                .retry_source_id
                .unwrap_or(config.original_destination_id),
        )?;
        initial.install_alternate_read(match config.side {
            Side::Client => pair.server,
            Side::Server => pair.client,
        })?;
    }
    let initial_exchange = initial::Exchange::new();
    // These are the actual write keys, shared only for synchronous owner access.
    // Timer readiness is derived from them, never a mirrored phase/availability flag.
    let write_keys = RefCell::new(wire::WriteKeys {
        initial: &initial,
        handshake: None,
        application: None,
    });
    let message_buffer = source
        .source
        .take_message_buffer()
        .map_err(|_| Error::Binding)?;
    let message_slot = crate::tls::handshake::local::MessageSlot::new(message_buffer);
    let (mut tx, mut rx, mut clock_book, mut publication, mut retirement) = book.split()?;
    let mut pending_handshake = None;
    let first_response = retry_client::run(
        &mut roles.tls_tx,
        &mut roles.udp,
        source,
        config,
        early.is_some(),
        &initial,
        &mut tx,
        &mut rx,
        &mut clock_book,
        &mut publication,
        receive_io,
        send_io,
        clock,
        issuer,
        &mut integrity,
        &mut pending_handshake,
    )
    .await?;
    let config = if let Some(retry) = first_response
        .as_ref()
        .and_then(|first| first.retry.as_ref())
    {
        *storage.peer.borrow_mut() = retry.source;
        Config {
            retry_source_id: Some(retry.source.bytes()),
            initial_token: retry.token(),
            peer_connection_id: retry.source.bytes(),
            ..config
        }
    } else {
        config
    };
    early_client::run(
        roles,
        source,
        early,
        config,
        &initial,
        &mut tx,
        &mut publication,
        send_io,
        clock,
        issuer,
        adapter_outcome,
    )
    .await?;
    let numbers = transcript::Numbers::new(source);
    let handoff = hibana_tls::handshake::key_source::Handoff::<P>::new();
    let mut initial_owner = tx.initial_retirement_owner();
    let (mut receive_initial, publish_initial) = match config.side {
        Side::Client => (None, Some(&mut roles.initial_event)),
        Side::Server => (Some(&mut roles.initial_event), None),
    };
    let mut received = None;
    let mut transmitted = None;
    {
        let mut receive = pin!(async {
            received = Some(
                local::receive(
                    &mut roles.rx,
                    &mut roles.receive_stop,
                    receive_io,
                    &message_slot,
                    storage,
                    config,
                    &initial,
                    &initial_exchange,
                    receive_initial.as_deref_mut(),
                    integrity,
                    first_response.as_ref(),
                    pending_handshake.take(),
                    reassembly,
                    &mut rx,
                    clock,
                )
                .await?,
            );
            Ok(())
        });
        let mut transmit = pin!(async {
            transmitted = Some(
                local::transmit(
                    &mut roles.tx,
                    &mut roles.tx_wire,
                    storage,
                    config,
                    scope,
                    &initial,
                    &write_keys,
                    &mut tx,
                    clock,
                )
                .await?,
            );
            Ok(())
        });
        let mut tls_receive = pin!(transcript::receive(
            &mut roles.tls_rx,
            &numbers,
            &handoff,
            &message_slot,
            config.side
        ));
        let mut key_handoff = pin!(transcript::handoff(
            &mut roles.tls_handoff,
            &handoff,
            storage
        ));
        let mut tls_transmit = pin!(transcript::transmit(
            &mut roles.tls_tx,
            &mut roles.tls_complete,
            &numbers,
            storage
        ));
        let mut publish = pin!(local::publish(
            &mut roles.udp,
            send_io,
            storage,
            &initial,
            &initial_exchange,
            publish_initial,
            issuer,
            adapter_outcome,
            &mut publication
        ));
        let mut timer = pin!(timer::run(
            &mut roles.timer,
            &mut roles.timer_stop,
            storage,
            &write_keys,
            &mut clock_book,
            clock
        ));
        let mut timer_receiver = pin!(timer::receive(&mut roles.timer_tx, &storage.schedule));
        let mut initial_retirement = pin!(initial::retire(
            &mut roles.initial_owner,
            &initial,
            &initial_exchange,
            &storage.schedule,
            &mut initial_owner,
            config.side
        ));
        crate::runtime::TaskSet::new([
            receive.as_mut(),
            transmit.as_mut(),
            tls_receive.as_mut(),
            tls_transmit.as_mut(),
            key_handoff.as_mut(),
            publish.as_mut(),
            timer.as_mut(),
            timer_receiver.as_mut(),
            initial_retirement.as_mut(),
        ])
        .await?;
    }
    if initial.available() {
        return Err(Error::Binding);
    }
    numbers.restore_buffer(message_slot.into_buffer().map_err(Error::Transcript)?)?;
    numbers.record_verified_consumed(received.as_ref().ok_or(Error::Binding)?.verified_consumed)?;
    retirement.disarm();
    let pending = storage.pending_application.borrow_mut().take();
    Ok((
        received.ok_or(Error::Binding)?,
        transmitted.ok_or(Error::Binding)?,
        pending,
    ))
}
