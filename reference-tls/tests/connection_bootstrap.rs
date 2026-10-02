//! No-network qualification of the actual complete host role bootstrap.
#![allow(long_running_const_eval)]
#[path = "../src/bin/support/connection_roles.rs"]
mod connection_roles;

use hibana_quic::{
    crypto,
    early_data::ServerPolicy,
    handshake_endpoint::{InitialKeyProtection, NetworkConfig, Side},
    path::Address,
    roles::{early_owner::ServiceCompletion, path_owner::Destination},
    streams::Limits,
};
use hibana_quic_host::async_io::Reactor;
use std::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
    time::Duration,
};

fn run(side: Side, early: bool) {
    // The host-profile future deliberately contains fixed owner backing stores.
    // A larger host test stack is unrelated to the no_alloc core guarantee.
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let reactor = Reactor::<0, 1>::new().unwrap();
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
            let config = connection_roles::Config {
                network: NetworkConfig::new(Address {
                    local: "127.0.0.1:4433".parse().unwrap(),
                    remote: "127.0.0.1:4434".parse().unwrap(),
                }),
                local_cid: Destination::new(b"localcid").unwrap(),
                bootstrap_destination: Destination::new(b"bootstrap").unwrap(),
                local_limits: Limits {
                    max_data: 4 * 16384,
                    max_streams_bidi: 4,
                    max_streams_uni: 4,
                    stream_data_bidi_local: 16384,
                    stream_data_bidi_remote: 16384,
                    stream_data_uni: 16384,
                },
                early_send: false,
                early_receive: early.then_some(ServerPolicy::BufferedReplaySafeRequests {
                    max_bytes: 4096,
                    max_streams: 4,
                }),
            };
            let mut execution = pin!(connection_roles::with_connection(
                keys,
                side,
                44,
                provider,
                config,
                async move |mut initial, tls, recovery, authority, path, stream, mut starter| {
                    assert_eq!(authority.generation(), 44);
                    assert_eq!(initial.generation(), 44);
                    assert_eq!(recovery.snapshot().generation, 44);
                    assert_eq!(
                        recovery.snapshot().active_path,
                        Some(path.snapshot().active)
                    );
                    assert_eq!(path.snapshot().initial_address, config.network.initial);
                    assert!(!path.snapshot().confirmed);
                    assert_eq!(stream.snapshot().local_limits, config.local_limits);
                    assert!(!stream.snapshot().ready);
                    assert!(!stream.snapshot().early_send_configured);
                    assert_eq!(starter.is_some(), early);
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
                        match side {
                            Side::Client => (server_mask, client_mask),
                            Side::Server => (client_mask, server_mask),
                        }
                    );
                    if let Some(starter) = starter.as_mut() {
                        // No replay claim was fabricated. This must be reported
                        // as unused resource cancellation, never Retired.
                        starter.close();
                    }
                    stream
                        .retire()
                        .await
                        .map_err(|e| format!("Stream retire: {e:?}"))?;
                    path.retire()
                        .await
                        .map_err(|e| format!("Path retire: {e:?}"))?;
                    recovery
                        .retire()
                        .await
                        .map_err(|e| format!("Recovery retire: {e:?}"))?;
                    initial
                        .retire()
                        .await
                        .map_err(|e| format!("Initial retire: {e:?}"))?;
                    tls.retire()
                        .await
                        .map_err(|e| format!("TLS retire: {e:?}"))?;
                    Ok(44)
                },
            ));
            // A broken role continuation must fail this test rather than park
            // forever. Both futures use the reactor's real eventfd-backed waker.
            let mut deadline = pin!(reactor.sleep(Duration::from_secs(5)).unwrap());
            let mut bounded = pin!(poll_fn(|cx| {
                if let Poll::Ready(result) = execution.as_mut().poll(cx) {
                    return Poll::Ready(result);
                }
                match deadline.as_mut().poll(cx) {
                    Poll::Ready(Ok(())) => {
                        Poll::Ready(Err("full owner bootstrap timed out".into()))
                    }
                    Poll::Ready(Err(error)) => {
                        Poll::Ready(Err(format!("bootstrap timer: {error}")))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }));
            let completed = reactor.block_on(bounded.as_mut()).unwrap().unwrap();
            assert_eq!(completed.application, 44);
            assert_eq!(
                completed.early,
                early.then_some(ServiceCompletion::UnactivatedCancelled)
            );
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn ordinary_bootstrap_connects_actual_owners_and_retires() {
    run(Side::Client, false);
    run(Side::Server, false);
}

#[test]
fn optional_unactivated_early_is_explicit_resource_cancellation() {
    run(Side::Server, true);
}
