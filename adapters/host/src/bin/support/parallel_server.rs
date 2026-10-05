//! Host admission and routing run beside independent Hibana connection owners.
//! The scheduler joins futures; it does not implement QUIC protocol phases.
use super::*;
use hibana_quic::{
    mailbox::Mailbox,
    runtime::{Task, TaskSet},
};
use hibana_quic_host::receive_routes::{Delivery, Dispatcher, Receiver};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
};
const MAX: usize = 64;
const BYTES: usize = direct_bootstrap::DATAGRAM;
struct Admission {
    address: Address,
    original: Vec<u8>,
    peer: Vec<u8>,
    local: [u8; 8],
    first: Vec<u8>,
    receiver: Receiver<BYTES>,
}

pub async fn run<const S: usize, const T: usize>(
    reactor: &HostReactor<S, T>,
    clock: &HostClock<'_, S, T>,
    listen: SocketAddr,
    credentials: (&std::path::Path, &std::path::Path),
    files: &cli::ServerFiles,
    cipher: hibana_quic::bounded_tls::CipherPolicy,
    count: usize,
) -> Result<Report> {
    if count == 0 || count > MAX {
        return Err("parallel connection capacity".into());
    }
    let (cert, key_path) = credentials;
    let certificates = pem::certificates(cert)?;
    let key = signing_key(&pem::private_key(key_path)?)?;
    let chain: Vec<&[u8]> = certificates.iter().map(|cert| cert.as_ref()).collect();
    let raw = UdpSocket::bind(listen).map_err(|e| format!("UDP bind: {e}"))?;
    let socket = reactor
        .register_udp(raw.try_clone().map_err(|e| format!("UDP clone: {e}"))?)
        .map_err(|e| format!("UDP registration: {e}"))?;
    eprintln!(
        "direct Hibana server listening on {}",
        socket.local_addr().map_err(|e| e.to_string())?
    );
    let mut slots: [[Option<Admission>; 1]; MAX] = std::array::from_fn(|_| [None]);
    let mailboxes = slots
        .each_mut()
        .map(|slot| Mailbox::new(slot).expect("one empty assignment slot"));
    let (mut senders, receivers): (Vec<_>, Vec<_>) = mailboxes
        .iter()
        .map(|m| m.split().expect("unique assignment halves"))
        .unzip();
    let results: RefCell<Vec<Option<Result<Report>>>> =
        RefCell::new((0..count).map(|_| None).collect());
    let mut workers: Vec<Pin<Box<dyn Future<Output = Result<()>> + '_>>> = Vec::new();
    for (index, mut assignment) in receivers.into_iter().enumerate() {
        let results = &results;
        let raw = &raw;
        let chain = &chain;
        let key = &key;
        workers.push(Box::pin(async move {
            if index >= count {
                return Ok(());
            }
            let mut admission = assignment.recv().await.map_err(|_| "admission closed")?;
            let result = async {
                // A duplicate descriptor shares the bound UDP socket, but owns
                // its own pending write registration. Only the dispatcher reads.
                // The original DatagramTx still returns Ready in the same poll
                // as actual sendmsg acceptance; no queued acceptance is invented.
                let tx = reactor
                    .register_udp(raw.try_clone().map_err(|e| format!("UDP clone: {e}"))?)
                    .map_err(|e| format!("TX registration: {e}"))?;
                let mut server = host_files::FileServer::new(
                    &files.www,
                    files.max_requests.unwrap_or(host_files::MAX_REQUESTS),
                )?;
                server.completion_limit = core::num::NonZeroUsize::new(1);
                let files = direct_bootstrap::Files::Server(server);
                let parameters = parameters(
                    &admission.local,
                    Some(&admission.original),
                    Some(files.local_limits()),
                )?;
                let mut buffers = TlsBuffers::new();
                let tls = BoundedTls::server_with_policy(
                    ServerConfig {
                        certificate_chain: chain,
                        signing_key: key,
                        transport_parameters: &parameters,
                    },
                    buffers.storage(),
                    &mut OsRng,
                    cipher,
                )
                .map_err(|e| format!("server TLS: {e:?}"))?;
                connected(
                    &tx,
                    clock,
                    admission.address,
                    Config {
                        side: Side::Server,
                        local_connection_id: &admission.local,
                        original_destination_id: &admission.original,
                        peer_connection_id: &admission.peer,
                    },
                    tls,
                    Some(&admission.first),
                    Some(files),
                    None,
                    0,
                    Some(&mut admission.receiver),
                )
                .await
            }
            .await;
            // Keep an actual failure separate. It never supplies a successful
            // connection report, and does not prevent other owners progressing.
            if std::env::var_os("HIBANA_QUIC_DIAGNOSTICS").is_some() {
                match &result {
                    Ok(report) => eprintln!(
                        "connection-terminal index={} idle={} closed={}",
                        index,
                        report.idle_expired_connections,
                        report
                            .application
                            .as_ref()
                            .is_some_and(|app| app.close_completed)
                    ),
                    Err(error) => {
                        eprintln!("connection-terminal index={} failure={}", index, error)
                    }
                }
            }
            results.borrow_mut()[index] = Some(result);
            Ok(())
        }));
    }
    let refs: Vec<Task<'_, String>> = workers
        .iter_mut()
        .map(|f| f.as_mut() as Task<'_, String>)
        .collect();
    let refs: [Task<'_, String>; MAX] = match refs.try_into() {
        Ok(array) => array,
        Err(_) => unreachable!("fixed worker count"),
    };
    let mut joined = Box::pin(TaskSet::new(refs));
    let mut ingress = Box::pin(async {
        let mut routes =
            Dispatcher::<BYTES>::new(count, 8).map_err(|e| format!("routes: {e:?}"))?;
        let mut seen: Vec<(Address, Vec<u8>)> = Vec::with_capacity(count);
        let mut bytes = [0; BYTES];
        loop {
            hibana_quic::runtime::yield_now().await;
            let metadata = match socket.recv_from(&mut bytes).await {
                Ok(value) => value,
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => continue,
                Err(e) => return Err::<(), String>(format!("UDP receive: {e}")),
            };
            let address = Address {
                local: metadata.local,
                remote: metadata.source,
            };
            let Some(Ok(packet)) = PacketIter::new(&bytes[..metadata.len], 8, 8)
                .ok()
                .and_then(|mut p| p.next())
            else {
                continue;
            };
            let destination = match packet.header {
                Header::Long { destination_id, .. } | Header::Short { destination_id, .. } => {
                    destination_id
                }
                _ => continue,
            };
            match routes.deliver(address, destination, &bytes[..metadata.len]) {
                Delivery::Queued | Delivery::Full | Delivery::Oversized => continue,
                Delivery::Unknown => {}
            }
            let Header::Long {
                kind: LongType::Initial,
                destination_id,
                source_id,
                token,
                ..
            } = packet.header
            else {
                continue;
            };
            if metadata.len < 1200
                || destination_id.len() < 8
                || !token.is_empty()
                || seen.len() >= count
                || seen
                    .iter()
                    .any(|(path, id)| *path == address && id == destination_id)
            {
                continue;
            }
            let local = random::<8>()?;
            let receiver = routes
                .register(address, &[destination_id, &local])
                .map_err(|e| format!("route registration: {e:?}"))?;
            let index = seen.len();
            seen.push((address, destination_id.to_vec()));
            senders[index]
                .send(Admission {
                    address,
                    original: destination_id.to_vec(),
                    peer: source_id.to_vec(),
                    local,
                    first: bytes[..metadata.len].to_vec(),
                    receiver,
                })
                .await
                .map_err(|_| "connection admission abandoned")?;
        }
    });
    poll_fn(|cx| {
        if let Poll::Ready(result) = joined.as_mut().poll(cx) {
            return Poll::Ready(result);
        }
        if let Poll::Ready(result) = ingress.as_mut().poll(cx) {
            return Poll::Ready(result);
        }
        Poll::Pending
    })
    .await?;
    // All connection futures have settled before cancelling the one physical
    // pending receive. Its retained buffer and socket borrow stay owned here.
    drop(ingress);
    drop(joined);
    drop(workers);
    let mut aggregate: Option<Report> = None;
    for result in results.into_inner() {
        let report = result.ok_or("missing connection result")??;
        aggregate = Some(match aggregate {
            Some(previous) => report.append(previous)?,
            None => report,
        });
    }
    aggregate.ok_or_else(|| "no connection result".into())
}
