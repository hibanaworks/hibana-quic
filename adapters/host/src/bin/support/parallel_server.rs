//! Host admission and routing run beside independent Hibana connection owners.
//! The scheduler joins futures; it does not implement QUIC protocol phases.
use super::*;
use hibana_quic::connection::Clock as _;
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
// Only synchronous ticket operations borrow the root-owned key. No worker can
// extract it, clone its nonce counter, or hold a mutable borrow across an await.
struct TicketAccess<'a, 'key>(&'a RefCell<ticket::TicketKey<'key>>);
impl ticket::ServerTicketStore for TicketAccess<'_, '_> {
    fn prepare(
        &mut self,
        rng: &mut dyn rand_core::CryptoRngCore,
        now_ms: u64,
        lifetime_seconds: u32,
        suite: u16,
        binding: ticket::Binding,
    ) -> std::result::Result<ticket::IssueToken, ticket::Error> {
        self.0
            .try_borrow_mut()
            .map_err(|_| ticket::Error::InvalidBinding)?
            .prepare(rng, now_ms, lifetime_seconds, suite, binding)
    }
    fn seal(
        &mut self,
        token: ticket::IssueToken,
        psk: hibana_quic::tls_schedule::Secret32,
        out: &mut [u8],
    ) -> std::result::Result<ticket::IssuedTicket, ticket::Error> {
        self.0
            .try_borrow_mut()
            .map_err(|_| ticket::Error::InvalidBinding)?
            .seal(token, psk, out)
    }
    fn accept(
        &mut self,
        bytes: &[u8],
        request: ticket::Acceptance<'_>,
    ) -> std::result::Result<ticket::AcceptedTicket, ticket::Error> {
        self.0
            .try_borrow_mut()
            .map_err(|_| ticket::Error::InvalidBinding)?
            .accept(bytes, request)
    }
    fn check(
        &mut self,
        bytes: &[u8],
        request: ticket::Acceptance<'_>,
    ) -> std::result::Result<ticket::AcceptedTicket, ticket::Error> {
        self.0
            .try_borrow_mut()
            .map_err(|_| ticket::Error::InvalidBinding)?
            .check(bytes, request)
    }
}
struct Admission {
    address: Address,
    original: Vec<u8>,
    peer: Vec<u8>,
    local: [u8; 8],
    first: Vec<u8>,
    ecn: Option<hibana_quic::ecn::Codepoint>,
    new_token: [u8; hibana_quic::new_token::TOKEN_LEN],
    receiver: Receiver<BYTES>,
}

pub async fn run<const S: usize, const T: usize>(
    reactor: &HostReactor<S, T>,
    clock: &HostClock<'_, S, T>,
    listen: SocketAddr,
    credentials: (&std::path::Path, &std::path::Path),
    files: &cli::ServerFiles,
    cipher: hibana_quic::bounded_tls::CipherPolicy,
    version: hibana_quic::version::Version,
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
    let mut replay = [];
    let ticket_owner = RefCell::new(
        ticket::TicketKey::generate(
            &mut OsRng,
            ticket::ReplayPolicy::ReusableOneRtt,
            &mut replay,
        )
        .map_err(|e| format!("ticket key: {e:?}"))?,
    );
    let ticket_clock = WallTicketClock;
    let mut workers: Vec<Pin<Box<dyn Future<Output = Result<()>> + '_>>> = Vec::new();
    for (index, mut assignment) in receivers.into_iter().enumerate() {
        let results = &results;
        let raw = &raw;
        let chain = &chain;
        let key = &key;
        let ticket_owner = &ticket_owner;
        let ticket_clock = &ticket_clock;
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
                let mut server = host_files::FileServer::new(Default::default(), 
                    &files.www,
                    files.max_requests.unwrap_or(host_files::MAX_REQUESTS),
                )?;
                server.completion_limit = core::num::NonZeroUsize::new(1);
                let files = direct_bootstrap::Files::Server(server);
                let parameters = parameters(
                    version,
                    &admission.local,
                    Some(&admission.original),
                    Some(files.local_limits()),
                    None,
                )?;
                let mut buffers = TlsBuffers::new();
                let mut tickets = TicketAccess(ticket_owner);
                let mut entropy = OsRng;
                let tls = BoundedTls::server_with_tickets_and_policy(
                    ServerConfig {
                        protocol: Default::default(),
                        version,
                        certificate_chain: chain,
                        signing_key: key,
                        transport_parameters: &parameters,
                    },
                    buffers.storage(),
                    &mut OsRng,
                    ServerResumption {
                        store: &mut tickets,
                        entropy: &mut entropy,
                        clock: ticket_clock,
                        policy: b"hibana-quic fixed-path hq v1",
                        lifetime_seconds: 3600,
                        max_age_skew_ms: 300000,
                    },
                    cipher,
                )
                .map_err(|e| format!("server TLS: {e:?}"))?;
                connected(
                    &tx,
                    None,
                    clock,
                    admission.address,
                    Config {
                        local_preferred: None,
                        initial_path: Some(admission.address),
                        version,
                        side: Side::Server,
                        local_connection_id: &admission.local,
                        original_destination_id: &admission.original,
                        retry_source_id: None,
                        initial_token: &[],
                        peer_connection_id: &admission.peer,
                    },
                    tls,
                    Some((&admission.first, admission.ecn)),
                    Some(files),
                    None,
                    0,
                    Some(&mut admission.receiver),
                    Some(&admission.new_token),
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
        let mut tokens = hibana_quic::new_token::Issuer::<MAX>::new();
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
            if respond_unsupported_version(&socket, &packet.header, metadata.source, metadata.len)
                .await?
            {
                continue;
            }
            let destination = match packet.header {
                Header::Long { destination_id, .. } | Header::Short { destination_id, .. } => {
                    destination_id
                }
                _ => continue,
            };
            match routes.deliver(address, destination, &bytes[..metadata.len], metadata.ecn) {
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
                || seen.len() >= count
                || seen
                    .iter()
                    .any(|(path, id)| *path == address && id == destination_id)
            {
                continue;
            }
            // Do not pin a damaged plaintext source CID or spend an admission
            // slot before checking the Initial's authenticated associated data.
            if initial_integrity(&packet).is_none() {
                continue;
            }
            // A previous NEW_TOKEN is checked only for a new admission. Routing
            // above handles repeated Initials for an already-owned connection.
            // Even a valid token currently retains the conservative amplification
            // limit until this connection supplies ordinary handshake evidence.
            let _address_token_valid = tokens
                .consume(token, address.remote.ip(), clock.now())
                .map_err(|e| format!("address token validation: {e:?}"))?;
            let new_token = tokens
                .issue(address.remote.ip(), clock.now(), &mut OsRng)
                .map_err(|e| format!("address token issuance: {e:?}"))?;
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
                    ecn: metadata.ecn,
                    new_token,
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

#[cfg(test)]
mod tests {
    use super::*;
    use ticket::ServerTicketStore;

    #[test]
    fn interleaved_workers_share_unique_issuance_and_disable_early_data() {
        let mut replay = [];
        let owner = RefCell::new(
            ticket::TicketKey::generate(
                &mut OsRng,
                ticket::ReplayPolicy::ReusableOneRtt,
                &mut replay,
            )
            .unwrap(),
        );
        let mut a = TicketAccess(&owner);
        let mut b = TicketAccess(&owner);
        let binding = ticket::Binding::new("localhost", b"hq-interop", b"test").unwrap();
        assert!(!a.supports_early());
        assert!(!b.supports_early());
        let first = a.prepare(&mut OsRng, 1000, 60, 0x1301, binding).unwrap();
        let second = b.prepare(&mut OsRng, 1000, 60, 0x1301, binding).unwrap();
        assert_ne!(first.ticket_nonce(), second.ticket_nonce());
        let abandoned = *first.ticket_nonce();
        drop(first);
        let third = a.prepare(&mut OsRng, 1000, 60, 0x1301, binding).unwrap();
        assert_ne!(&abandoned, third.ticket_nonce());
        assert_ne!(second.ticket_nonce(), third.ticket_nonce());
        let held = owner.borrow_mut();
        assert!(matches!(
            b.prepare(&mut OsRng, 1000, 60, 0x1301, binding),
            Err(ticket::Error::InvalidBinding)
        ));
        drop(held);
        assert!(b.prepare(&mut OsRng, 1000, 60, 0x1301, binding).is_ok());
    }
}
