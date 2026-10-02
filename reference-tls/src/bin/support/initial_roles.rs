//! Shared resource bootstrap for development handshake adapters.
//!
//! The actual role-local protocol awaits and key ownership remain in
//! roles::packet_protection and roles::tls_owner. This helper only allocates caller-owned bounded
//! storage, attaches both facets of one projected session, and retains every
//! endpoint value until the borrowed actors and application have finished.
use hibana::{
    g,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
use hibana_quic::{
    carrier::CarrierStorage,
    crypto::InitialKeys,
    handshake_endpoint::{
        INITIAL_PACKET_BYTES, InitialKeyClient, InitialProtection, Side, TlsClient,
    },
    mailbox::Mailbox,
    roles::{
        packet_protection::{self, Command, Exchange, Reply},
        protocol::key_choreography,
        protocol_tls::tls_choreography,
        tls_owner,
    },
    runtime::{Task, TaskSet},
};
use std::pin::pin;

pub async fn with_connection<T: hibana_quic::tls::Provider, R>(
    keys: InitialKeys,
    side: Side,
    generation: u64,
    provider: T,
    application: impl for<'channel, 'storage, 'tc, 'ts> AsyncFnOnce(
        InitialProtection<'channel, 'storage>,
        TlsClient<'tc, 'ts>,
    ) -> Result<R, String>,
) -> Result<R, String> {
    let (receive_key, transmit_key) = match side {
        Side::Client => (keys.server, keys.client),
        Side::Server => (keys.client, keys.server),
    };
    let carrier = CarrierStorage::<1, 16, 64>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(2);
    let rv = kit
        .rendezvous(
            &mut slab,
            carrier
                .bind(sid)
                .map_err(|e| format!("Initial carrier: {e:?}"))?,
        )
        .map_err(|e| format!("Initial rendezvous: {e:?}"))?;
    let global = g::par(
        g::par(key_choreography::<16, 17>(), key_choreography::<18, 19>()),
        tls_choreography::<24, 25>(),
    );
    let p16 = project::<16, _>(&global);
    let p17 = project::<17, _>(&global);
    let p18 = project::<18, _>(&global);
    let p19 = project::<19, _>(&global);
    let p24 = project::<24, _>(&global);
    let p25 = project::<25, _>(&global);
    let mut e16 = rv
        .enter(sid, &p16)
        .map_err(|e| format!("Initial RX client: {e:?}"))?;
    let mut e17 = rv
        .enter(sid, &p17)
        .map_err(|e| format!("Initial RX crypto: {e:?}"))?;
    let mut e18 = rv
        .enter(sid, &p18)
        .map_err(|e| format!("Initial TX client: {e:?}"))?;
    let mut e19 = rv
        .enter(sid, &p19)
        .map_err(|e| format!("Initial TX crypto: {e:?}"))?;
    let mut e24 = rv
        .enter(sid, &p24)
        .map_err(|e| format!("TLS client attach: {e:?}"))?;
    let mut e25 = rv
        .enter(sid, &p25)
        .map_err(|e| format!("TLS owner attach: {e:?}"))?;
    let mut tls_commands: [Option<tls_owner::Command<1536>>; 1] = [None];
    let mut tls_replies: [Option<tls_owner::Reply<1536, 512>>; 1] = [None];
    let tls_commands =
        Mailbox::new(&mut tls_commands).map_err(|e| format!("TLS mailbox: {e:?}"))?;
    let tls_replies = Mailbox::new(&mut tls_replies).map_err(|e| format!("TLS replies: {e:?}"))?;
    let (tls_send, tls_recv) = tls_commands
        .split()
        .map_err(|e| format!("TLS split: {e:?}"))?;
    let (tls_reply_send, tls_reply_recv) = tls_replies
        .split()
        .map_err(|e| format!("TLS reply split: {e:?}"))?;
    let mut tls_exchange = tls_owner::Exchange::new();
    let mut rx_commands: [Option<Command<INITIAL_PACKET_BYTES>>; 1] = [None];
    let mut rx_replies: [Option<Reply<INITIAL_PACKET_BYTES>>; 1] = [None];
    let mut tx_commands: [Option<Command<INITIAL_PACKET_BYTES>>; 1] = [None];
    let mut tx_replies: [Option<Reply<INITIAL_PACKET_BYTES>>; 1] = [None];
    let rx_commands =
        Mailbox::new(&mut rx_commands).map_err(|e| format!("Initial RX mailbox: {e:?}"))?;
    let rx_replies =
        Mailbox::new(&mut rx_replies).map_err(|e| format!("Initial RX replies: {e:?}"))?;
    let tx_commands =
        Mailbox::new(&mut tx_commands).map_err(|e| format!("Initial TX mailbox: {e:?}"))?;
    let tx_replies =
        Mailbox::new(&mut tx_replies).map_err(|e| format!("Initial TX replies: {e:?}"))?;
    let (rx_client_send, rx_role_recv) = rx_commands
        .split()
        .map_err(|e| format!("Initial RX split: {e:?}"))?;
    let (rx_role_send, rx_client_recv) = rx_replies
        .split()
        .map_err(|e| format!("Initial RX replies split: {e:?}"))?;
    let (tx_client_send, tx_role_recv) = tx_commands
        .split()
        .map_err(|e| format!("Initial TX split: {e:?}"))?;
    let (tx_role_send, tx_client_recv) = tx_replies
        .split()
        .map_err(|e| format!("Initial TX replies split: {e:?}"))?;
    let mut rx_exchange = Exchange::new();
    let mut tx_exchange = Exchange::new();
    let mut result = None;
    {
        let mut work = pin!(async {
            let tls = TlsClient::connect(tls_send, tls_reply_recv, generation)
                .await
                .map_err(|e| format!("TLS connect: {e:?}"))?;
            let receive = InitialKeyClient::connect(rx_client_send, rx_client_recv, generation)
                .await
                .map_err(|e| format!("Initial RX connect: {e:?}"))?;
            let transmit = InitialKeyClient::connect(tx_client_send, tx_client_recv, generation)
                .await
                .map_err(|e| format!("Initial TX connect: {e:?}"))?;
            let initial = InitialProtection::new(receive, transmit)
                .map_err(|e| format!("Initial capabilities: {e:?}"))?;
            result = Some(application(initial, tls).await?);
            Ok::<(), String>(())
        });
        let mut receive_actor = pin!(async {
            packet_protection::run_borrowed(
                &mut e16,
                &mut e17,
                generation,
                receive_key,
                rx_role_recv,
                rx_role_send,
                &mut rx_exchange,
            )
            .await
            .map_err(|e| format!("Initial RX role: {e:?}"))
        });
        let mut transmit_actor = pin!(async {
            packet_protection::run_borrowed(
                &mut e18,
                &mut e19,
                generation,
                transmit_key,
                tx_role_recv,
                tx_role_send,
                &mut tx_exchange,
            )
            .await
            .map_err(|e| format!("Initial TX role: {e:?}"))
        });
        let mut tls_actor = pin!(async {
            tls_owner::run_borrowed(
                &mut e24,
                &mut e25,
                generation,
                provider,
                tls_recv,
                tls_reply_send,
                &mut tls_exchange,
            )
            .await
            .map_err(|e| format!("TLS owner: {e:?}"))
        });
        let tasks: [Task<'_, String>; 4] = [
            tls_actor.as_mut(),
            receive_actor.as_mut(),
            transmit_actor.as_mut(),
            work.as_mut(),
        ];
        TaskSet::new(tasks).await?;
    }
    result.ok_or_else(|| "missing completed handshake report".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hibana_quic::{crypto, handshake_endpoint::InitialKeyProtection};
    use hibana_quic_host::async_io::Reactor;

    #[test]
    fn real_bootstrap_uses_correct_directions_and_retires_without_udp() {
        // This reactor has zero socket slots: the test performs no network I/O.
        let reactor = Reactor::<0, 0>::new().unwrap();
        for side in [Side::Client, Side::Server] {
            let keys = crypto::initial_keys(b"bootstrap").unwrap();
            let sample = [0x37; 16];
            let client_mask = keys.client.header_mask(&sample).unwrap();
            let server_mask = keys.server.header_mask(&sample).unwrap();
            let provider = hibana_quic_reference_tls::RustlsProvider::client(
                hibana_quic_reference_tls::rustls::RootCertStore::empty(),
                hibana_quic_reference_tls::rustls::pki_types::ServerName::try_from("localhost")
                    .unwrap(),
                vec![],
            )
            .unwrap();
            let mut execution = pin!(with_connection(
                keys,
                side,
                44,
                provider,
                async move |mut initial, tls| {
                    assert_eq!(initial.generation(), 44);
                    let receive = initial
                        .receive_mask(sample)
                        .await
                        .map_err(|e| format!("RX: {e:?}"))?;
                    let transmit = initial
                        .transmit_mask(sample)
                        .await
                        .map_err(|e| format!("TX: {e:?}"))?;
                    assert_eq!(
                        (receive, transmit),
                        if side == Side::Client {
                            (server_mask, client_mask)
                        } else {
                            (client_mask, server_mask)
                        }
                    );
                    initial
                        .retire()
                        .await
                        .map_err(|e| format!("retire: {e:?}"))?;
                    tls.retire()
                        .await
                        .map_err(|e| format!("TLS retire: {e:?}"))?;
                    Ok(())
                }
            ));
            reactor.block_on(execution.as_mut()).unwrap().unwrap();
        }
    }
}
