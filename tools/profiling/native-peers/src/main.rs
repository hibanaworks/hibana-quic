use neqo_common::{Datagram, event::Provider};
use neqo_transport::{
    Connection, ConnectionEvent, ConnectionParameters, Output, RandomConnectionIdGenerator, State,
    StreamType, Version,
};
use nss::{AuthenticationStatus, TLS_AES_128_GCM_SHA256, TLS_GRP_EC_X25519, TLS_VERSION_1_3};
use std::{
    cell::RefCell,
    env, fs, io,
    net::{SocketAddr, UdpSocket as StdUdp},
    path::Path,
    process::{Child, Command, Stdio},
    rc::Rc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    time::{sleep, timeout},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

mod coverage;

struct Packet {
    direction: &'static str,
    elapsed: Duration,
    bytes: usize,
}

struct Measurement {
    elapsed: Duration,
    server_cpu: Option<Duration>,
    sent: usize,
    received: usize,
    packets: Vec<Packet>,
}

#[cfg(target_os = "macos")]
fn server_cpu(pid: u32) -> io::Result<Option<Duration>> {
    let pid = i32::try_from(pid).map_err(io::Error::other)?;
    let mut usage = core::mem::MaybeUninit::<libc::rusage_info_v0>::uninit();
    // SAFETY: V0 writes exactly rusage_info_v0 into this aligned output buffer.
    let status =
        unsafe { libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V0, usage.as_mut_ptr().cast()) };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful proc_pid_rusage initialized all V0 fields.
    let usage = unsafe { usage.assume_init() };
    let mut scale = mach2::mach_time::mach_timebase_info { numer: 0, denom: 0 };
    // SAFETY: scale is a writable mach_timebase_info of the required size.
    let status = unsafe { mach2::mach_time::mach_timebase_info(&mut scale) };
    if status != 0 || scale.denom == 0 {
        return Err(io::Error::other("Mach timebase unavailable"));
    }
    // XNU task_power_info_locked supplies these counters in Mach ticks.
    let ticks = u128::from(usage.ri_user_time) + u128::from(usage.ri_system_time);
    let nanos = ticks * u128::from(scale.numer) / u128::from(scale.denom);
    let nanos = u64::try_from(nanos).map_err(io::Error::other)?;
    Ok(Some(Duration::from_nanos(nanos)))
}

#[cfg(not(target_os = "macos"))]
fn server_cpu(_pid: u32) -> io::Result<Option<Duration>> {
    Ok(None)
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn request(
    remote: SocketAddr,
    path: &str,
    leaf: &[u8],
    expected: &[u8],
    server_pid: u32,
    profile: Option<&Path>,
) -> Result<Measurement> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local = socket.local_addr()?;
    // NSS initialization and socket binding are outside timing. Server work
    // performed after its UDP bind can still overlap this interval.
    let cpu_start = server_cpu(server_pid)?;
    let start = Instant::now();
    let params = ConnectionParameters::default()
        .versions(Version::Version1, vec![Version::Version1])
        .mlkem(false)
        .pmtud(false)
        .sni_slicing(false);
    let mut connection = Connection::new_client(
        "localhost",
        &["hq-interop"],
        Rc::new(RefCell::new(RandomConnectionIdGenerator::new(8))),
        local,
        remote,
        params,
        start,
    )?;
    connection.set_ciphers(&[TLS_AES_128_GCM_SHA256])?;
    connection.set_groups(&[TLS_GRP_EC_X25519])?;
    let mut stream = None;
    let mut body = Vec::new();
    let mut received = [0u8; 65536];
    let mut sent_packets = 0;
    let mut received_packets = 0;
    let mut packets = Vec::new();
    loop {
        while let Some(event) = connection.next_event() {
            match event {
                ConnectionEvent::AuthenticationNeeded => {
                    let chain = connection
                        .peer_certificate()
                        .ok_or("missing server certificate")?;
                    if chain.iter().next() != Some(leaf) {
                        return Err(
                            "server leaf does not match the pinned benchmark certificate".into(),
                        );
                    }
                    connection.authenticated(AuthenticationStatus::Ok, Instant::now());
                }
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    if Some(stream_id) != stream {
                        return Err("unexpected response stream".into());
                    }
                    let mut chunk = [0u8; 4096];
                    let (size, fin) = connection.stream_recv(stream_id, &mut chunk)?;
                    body.extend_from_slice(&chunk[..size]);
                    if body.len() > expected.len() {
                        return Err("oversized response".into());
                    }
                    if fin {
                        let elapsed = start.elapsed();
                        let cpu_end = server_cpu(server_pid)?;
                        let server_cpu = match (cpu_start, cpu_end) {
                            (Some(before), Some(after)) => Some(
                                after
                                    .checked_sub(before)
                                    .ok_or("CPU counter went backwards")?,
                            ),
                            (None, None) => None,
                            _ => return Err("CPU counter availability changed".into()),
                        };
                        if body != expected {
                            return Err("response bytes differ".into());
                        }
                        let info = connection.tls_info().ok_or("missing TLS info")?;
                        if info.version() != TLS_VERSION_1_3
                            || info.cipher_suite() != TLS_AES_128_GCM_SHA256
                            || info.key_exchange() != TLS_GRP_EC_X25519
                            || info.alpn() != Some("hq-interop")
                            || info.resumed()
                            || info.early_data_accepted()
                        {
                            return Err(format!("unexpected TLS parameters: {info:?}").into());
                        }
                        if let Some(profile) = profile {
                            coverage::snapshot(
                                server_pid,
                                profile,
                                &profile.with_extension("response.profraw"),
                            )?;
                        }
                        connection.close(Instant::now(), 0, "benchmark complete");
                        while let Output::Datagram(packet) =
                            connection.process_output(Instant::now())
                        {
                            socket.send_to(&packet, packet.destination()).await?;
                        }
                        return Ok(Measurement {
                            elapsed,
                            server_cpu,
                            sent: sent_packets,
                            received: received_packets,
                            packets,
                        });
                    }
                }
                ConnectionEvent::StateChange(State::Closed(reason)) => {
                    return Err(format!("closed before response: {reason:?}").into());
                }
                _ => {}
            }
        }
        if stream.is_none() && matches!(connection.state(), State::Connected | State::Confirmed) {
            let id = connection.stream_create(StreamType::BiDi)?;
            let request = format!("GET {path}\r\n");
            if connection.stream_send(id, request.as_bytes())? != request.len() {
                return Err("partial request admission".into());
            }
            connection.stream_close_send(id)?;
            stream = Some(id);
        }
        let wait = loop {
            match connection.process_output(Instant::now()) {
                Output::Datagram(packet) => {
                    socket.send_to(&packet, packet.destination()).await?;
                    sent_packets += 1;
                    packets.push(Packet {
                        direction: "send",
                        elapsed: start.elapsed(),
                        bytes: packet.len(),
                    });
                }
                Output::Callback(delay) => break delay,
                Output::None => break Duration::from_secs(5),
            }
        };
        if let Ok(result) = timeout(
            wait.max(Duration::from_micros(1)),
            socket.recv_from(&mut received),
        )
        .await
        {
            let (size, source) = result?;
            if source != remote {
                return Err("unexpected UDP peer".into());
            }
            if size == 0 {
                return Err("empty UDP packet".into());
            }
            received_packets += 1;
            packets.push(Packet {
                direction: "recv",
                elapsed: start.elapsed(),
                bytes: size,
            });
            connection.process_input(
                Datagram::new(source, local, Default::default(), received[..size].to_vec()),
                Instant::now(),
            );
        }
    }
}

async fn trial(
    executable: &Path,
    kind: &str,
    dir: &Path,
    iteration: usize,
    leaf: &[u8],
    body: &[u8],
    label: &str,
) -> Result<Duration> {
    let reservation = StdUdp::bind("127.0.0.1:0")?;
    let address = reservation.local_addr()?;
    drop(reservation);
    let mut command = Command::new(executable);
    let profile = if kind == "hibana"
        && let Some(directory) = env::var_os("HIBANA_NATIVE_COVERAGE")
    {
        let directory = Path::new(&directory);
        fs::create_dir_all(directory)?;
        let raw = directory.join(format!("{label}-{iteration}-.profraw"));
        if [
            raw.clone(),
            raw.with_extension("ready.profraw"),
            raw.with_extension("response.profraw"),
        ]
        .iter()
        .any(|path| path.exists())
        {
            return Err("coverage output already exists; use a fresh directory".into());
        }
        command.env(
            "LLVM_PROFILE_FILE",
            directory.join(format!("{label}-{iteration}-%c.profraw")),
        );
        // LLVM expands %c to an empty string and maps the counters continuously.
        Some(raw)
    } else {
        None
    };
    if kind == "hibana" {
        command
            .arg(address.to_string())
            .arg(dir.join("cert.pem"))
            .arg(dir.join("key.pem"))
            .arg(dir.join("body"));
    } else {
        command
            .args(["--alpn", "hq-interop", "--db"])
            .arg(dir.join("nssdb"))
            .args(["--key", "benchmark", "--ciphers", "TLS_AES_128_GCM_SHA256"])
            .arg(address.to_string());
    }
    let stdout = fs::File::create(dir.join(format!("{label}-{iteration}.out")))?;
    let stderr = fs::File::create(dir.join(format!("{label}-{iteration}.err")))?;
    let mut server = Server(
        command
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?,
    );
    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = server.0.try_wait()? {
                return Err(io::Error::other(format!("{kind} server exited: {status}")));
            }
            let sockets = Command::new("lsof")
                .args(["-nP", "-a", "-p"])
                .arg(server.0.id().to_string())
                .arg("-i")
                .arg(format!("UDP@{address}"))
                .arg("-Fpn")
                .output()?;
            if !sockets.status.success() && sockets.status.code() != Some(1) {
                return Err(io::Error::other(format!(
                    "socket inspection failed: {}",
                    String::from_utf8_lossy(&sockets.stderr)
                )));
            }
            if String::from_utf8_lossy(&sockets.stdout)
                .lines()
                .any(|line| line == format!("n{address}"))
            {
                return Ok(());
            }
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await??;
    if let Some(profile) = &profile {
        coverage::snapshot(
            server.0.id(),
            profile,
            &profile.with_extension("ready.profraw"),
        )?;
        if fs::read_to_string(dir.join(format!("{label}-{iteration}.err")))?
            .contains("LLVM Profile Error:")
        {
            return Err("LLVM could not map continuous counters; inspect server stderr".into());
        }
    }
    let mut sampler = if kind == "hibana"
        && let Some(directory) = env::var_os("HIBANA_NATIVE_STACKS")
    {
        let directory = Path::new(&directory);
        fs::create_dir_all(directory)?;
        let diagnostics = fs::File::create(directory.join(format!("{label}-{iteration}.err")))?;
        let child = Command::new("/usr/bin/sample")
            .arg(server.0.id().to_string())
            .args(["1", "1", "-mayDie", "-fullPaths", "-file"])
            .arg(directory.join(format!("{label}-{iteration}.sample")))
            .stdout(Stdio::null())
            .stderr(Stdio::from(diagnostics))
            .spawn()?;
        // Attach before the client starts. Sampling is separate from timing
        // comparisons, and the server still completes the same request.
        sleep(Duration::from_millis(200)).await;
        Some(Server(child))
    } else {
        None
    };
    let path = if kind == "hibana" { "/hello" } else { "/01537" };
    let measurement = timeout(
        Duration::from_secs(5),
        request(address, path, leaf, body, server.0.id(), profile.as_deref()),
    )
    .await??;
    // Both requests have the same byte length and both responses are 1,537 zeros.
    println!(
        "{label}\t{iteration}\t{}\t{}\t{}\t{}",
        measurement.elapsed.as_nanos(),
        measurement.sent,
        measurement.received,
        measurement.server_cpu.map_or_else(
            || "unavailable".to_owned(),
            |cpu| cpu.as_nanos().to_string()
        ),
    );
    for packet in &measurement.packets {
        eprintln!(
            "packet\t{label}\t{iteration}\t{}\t{}\t{}",
            packet.direction,
            packet.elapsed.as_nanos(),
            packet.bytes,
        );
    }
    if kind == "hibana" {
        timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = server.0.try_wait()? {
                    if !status.success() {
                        return Err(io::Error::other(format!("hibana server exited: {status}")));
                    }
                    return Ok(());
                }
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await??;
    }
    if let Some(sampler) = &mut sampler {
        let status = sampler.0.wait()?;
        if !status.success() {
            return Err(io::Error::other(format!("stack sampler exited: {status}")).into());
        }
    }
    Ok(measurement.elapsed)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 4 && args.len() != 5 {
        return Err(
            "usage: native-peer-comparison HIBANA_SERVER NEQO_SERVER CREDENTIAL_DIR SAMPLES [BASELINE_HIBANA_SERVER]".into(),
        );
    }
    let dir = Path::new(&args[2]);
    let leaf = fs::read(dir.join("cert.der"))?;
    let body = fs::read(dir.join("body"))?;
    if body != vec![0; 1537] {
        return Err("body must be 1,537 zero bytes".into());
    }
    let samples: usize = args[3].to_str().ok_or("invalid sample count")?.parse()?;
    if samples == 0 {
        return Err("sample count must be positive".into());
    }
    if env::var_os("HIBANA_NATIVE_STACKS").is_some() {
        eprintln!(
            "Stack sampling enabled. These durations are profiling data, not timing comparisons."
        );
    }
    if env::var_os("HIBANA_NATIVE_COVERAGE").is_some() {
        if args.len() == 5 || env::var_os("HIBANA_NATIVE_STACKS").is_some() {
            return Err(
                "coverage requires one instrumented Hibana server without stack sampling".into(),
            );
        }
        eprintln!(
            "LLVM continuous counters enabled. These durations are profiling data, not timing comparisons."
        );
    }
    nss::init()?;
    println!(
        "implementation\titeration\tconnection_to_response_ns\tclient_packets_sent\tclient_packets_received\tserver_cpu_ns"
    );
    let mut peers = vec![
        ("hibana", "hibana", Path::new(&args[0])),
        ("neqo", "neqo", Path::new(&args[1])),
    ];
    if let Some(baseline) = args.get(4) {
        peers.insert(0, ("hibana-before", "hibana", Path::new(baseline)));
    }
    let mut totals = vec![Vec::new(); peers.len()];
    for iteration in 0..samples + 2 {
        // Balance forward/reverse order and positions; exclude two warmups.
        // With three servers, six consecutive iterations cover all six orders.
        let mut order = (0..peers.len()).collect::<Vec<_>>();
        order.rotate_left((iteration / 2) % peers.len());
        if iteration % 2 != 0 {
            order.reverse();
        }
        for index in order {
            let (label, kind, executable) = peers[index];
            let elapsed = trial(executable, kind, dir, iteration, &leaf, &body, label).await?;
            if iteration >= 2 {
                totals[index].push(elapsed.as_nanos());
            }
        }
    }
    if peers.len() == 3 {
        let mut ratios = totals[1]
            .iter()
            .zip(&totals[0])
            .map(|(&after, &before)| after as f64 / before as f64)
            .collect::<Vec<_>>();
        let faster = ratios.iter().filter(|&&ratio| ratio < 1.0).count();
        ratios.sort_by(f64::total_cmp);
        eprintln!(
            "paired hibana/before samples={} faster={} p10={:.6} median={:.6} p90={:.6}",
            ratios.len(),
            faster,
            ratios[ratios.len() / 10],
            ratios[ratios.len() / 2],
            ratios[ratios.len() * 9 / 10],
        );
    }
    for (index, values) in totals.iter_mut().enumerate() {
        values.sort_unstable();
        eprintln!(
            "{} samples={} min_ns={} median_ns={} max_ns={}",
            peers[index].0,
            values.len(),
            values[0],
            values[values.len() / 2],
            values[values.len() - 1]
        );
    }
    Ok(())
}
