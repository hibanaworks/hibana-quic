//! Run the authenticated application examples, with one-case retry selection.
//! Build with `rustc +1.95.0 --edition=2024 -D warnings tests/check_examples.rs`.
use std::{
    env,
    error::Error,
    fs::{self, File},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

enum Case {
    Quic,
    Http {
        method: &'static str,
        path: &'static str,
        body: String,
        status: u16,
        expected: String,
    },
    Hq(usize),
}

fn cases() -> Vec<(&'static str, Case)> {
    let greeting = "hello from Hibana\n";
    vec![
        ("quic", Case::Quic),
        (
            "http3-get-hello",
            Case::Http {
                method: "GET",
                path: "/hello",
                body: String::new(),
                status: 200,
                expected: greeting.into(),
            },
        ),
        (
            "http3-head-hello",
            Case::Http {
                method: "HEAD",
                path: "/hello",
                body: String::new(),
                status: 200,
                expected: String::new(),
            },
        ),
        (
            "http3-post-echo",
            Case::Http {
                method: "POST",
                path: "/echo",
                body: greeting.into(),
                status: 200,
                expected: greeting.into(),
            },
        ),
        (
            "http3-post-8193",
            Case::Http {
                method: "POST",
                path: "/echo",
                body: "x".repeat(8193),
                status: 200,
                expected: "x".repeat(8193),
            },
        ),
        (
            "http3-get-missing",
            Case::Http {
                method: "GET",
                path: "/missing",
                body: String::new(),
                status: 404,
                expected: "not found\n".into(),
            },
        ),
        (
            "http3-head-missing",
            Case::Http {
                method: "HEAD",
                path: "/missing",
                body: String::new(),
                status: 404,
                expected: String::new(),
            },
        ),
        ("hq-0", Case::Hq(0)),
        ("hq-1", Case::Hq(1)),
        ("hq-16385", Case::Hq(16385)),
        ("hq-1048576", Case::Hq(1048576)),
    ]
}

struct Args {
    binaries: PathBuf,
    certificate: PathBuf,
    key: PathBuf,
    ca: PathBuf,
    evidence: PathBuf,
    selection: String,
}

fn arguments() -> Result<Args> {
    let values: Vec<_> = env::args_os().skip(1).collect();
    if values.len() != 6 {
        return Err("usage: check-examples BINARIES CERT KEY CA EVIDENCE all|CASE".into());
    }
    let selection = values[5]
        .to_str()
        .ok_or("case name must be UTF-8")?
        .to_owned();
    if selection != "all" && !cases().iter().any(|(name, _)| *name == selection) {
        return Err(format!("unknown application case {selection}").into());
    }
    Ok(Args {
        binaries: fs::canonicalize(&values[0])?,
        certificate: fs::canonicalize(&values[1])?,
        key: fs::canonicalize(&values[2])?,
        ca: fs::canonicalize(&values[3])?,
        evidence: values[4].clone().into(),
        selection,
    })
}

fn output_files(command: &mut Command, root: &Path, side: &str) -> Result<()> {
    command.stdin(Stdio::null());
    command.stdout(File::create(root.join(format!("{side}.stdout")))?);
    command.stderr(File::create(root.join(format!("{side}.stderr")))?);
    Ok(())
}

fn wait(child: &mut Child, limit: Duration) -> Result<ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "process {} exceeded {} seconds",
                child.id(),
                limit.as_secs()
            )
            .into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn listening(server: &mut Child, root: &Path) -> Result<SocketAddr> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let bytes = fs::read(root.join("server.stderr"))?;
        if let Some(stop) = bytes.iter().position(|byte| *byte == b'\n') {
            let line = std::str::from_utf8(&bytes[..stop])?;
            let address: SocketAddr = line
                .strip_prefix("listening on ")
                .ok_or_else(|| format!("unexpected listener output: {line}"))?
                .parse()?;
            if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || address.port() == 0 {
                return Err(format!("unexpected listener address {address}").into());
            }
            return Ok(address);
        }
        if let Some(status) = server.try_wait()? {
            return Err(format!("listener exited before readiness: {status}").into());
        }
        if Instant::now() >= deadline {
            return Err("listener did not become ready in 10 seconds".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn stop(child: &mut Child) {
    // Reap on success, assertion error and timeout; cleanup never changes the
    // recorded verdict or retries an exchange.
    let _ = child.kill();
    let _ = child.wait();
}

fn exchange(args: &Args, name: &str, case: &Case) -> Result<()> {
    let root = args.evidence.join(name);
    fs::create_dir(&root)?;
    let protocol = match case {
        Case::Quic => "quic",
        Case::Http { .. } => "http3",
        Case::Hq(_) => "hq",
    };
    let source = root.join("content");
    let destination = root.join("received");
    let mut server_command = Command::new(args.binaries.join(format!("{protocol}-server")));
    server_command
        .args(["127.0.0.1:0"])
        .arg(&args.certificate)
        .arg(&args.key);
    if let Case::Hq(size) = case {
        let bytes: Vec<_> = (0..*size)
            .map(|index| (index.wrapping_mul(73).wrapping_add(19) % 256) as u8)
            .collect();
        fs::write(&source, bytes)?;
        server_command.arg(&source);
    }
    output_files(&mut server_command, &root, "server")?;
    let started = Instant::now();
    let mut server = server_command.spawn()?;
    let result = (|| -> Result<()> {
        let address = listening(&mut server, &root)?;
        let mut client_command = Command::new(args.binaries.join(format!("{protocol}-client")));
        client_command.arg(address.to_string()).arg(&args.ca);
        if let Case::Hq(_) = case {
            client_command.arg(&destination);
        }
        if let Case::Http {
            method, path, body, ..
        } = case
        {
            client_command
                .env("HTTP_METHOD", method)
                .env("HTTP_PATH", path)
                .env("HTTP_BODY", body);
        }
        output_files(&mut client_command, &root, "client")?;
        let mut client = client_command.spawn()?;
        let client_result = wait(&mut client, Duration::from_secs(40));
        stop(&mut client);
        let client_status = client_result?;
        let server_status = wait(&mut server, Duration::from_secs(40))?;
        fs::write(
            root.join("status.txt"),
            format!(
                "client={client_status}\nserver={server_status}\nelapsed_ms={}\n",
                started.elapsed().as_millis()
            ),
        )?;
        if !client_status.success() || !server_status.success() {
            return Err(format!("client={client_status}, server={server_status}").into());
        }
        let client_output = fs::read(root.join("client.stdout"))?;
        let server_output = fs::read(root.join("server.stdout"))?;
        match case {
            Case::Quic => {
                if client_output != b"42 squared = 1764\n7 squared = 49\n" {
                    return Err("QUIC response mismatch".into());
                }
            }
            Case::Http {
                status, expected, ..
            } => {
                let diagnostics = fs::read_to_string(root.join("client.stderr"))?;
                if client_output != expected.as_bytes()
                    || !diagnostics.contains(&format!("HTTP/3 {status}\n"))
                    || server_output != b"served HTTP/3 request\n"
                {
                    return Err("HTTP/3 response content, status or completion mismatch".into());
                }
            }
            Case::Hq(_) => {
                if client_output != b"received response\n" || server_output != b"served response\n"
                {
                    return Err("HQ response completion mismatch".into());
                }
                if fs::read(&source)? != fs::read(&destination)? {
                    return Err("HQ response content mismatch".into());
                }
            }
        }
        Ok(())
    })();
    stop(&mut server);
    match result {
        Ok(()) => {
            fs::write(root.join("verdict.txt"), "passed\n")?;
            println!(
                "{name}: authenticated response, normal close and resource retirement passed ({}ms)",
                started.elapsed().as_millis()
            );
            Ok(())
        }
        Err(error) => {
            fs::write(root.join("verdict.txt"), format!("failed: {error}\n"))?;
            eprintln!("{name}: {error}; evidence={}", root.display());
            for side in ["client", "server"] {
                if let Ok(text) = fs::read_to_string(root.join(format!("{side}.stderr"))) {
                    eprintln!("{side} stderr:\n{text}");
                }
            }
            Err(error)
        }
    }
}

fn run() -> Result<()> {
    let args = arguments()?;
    fs::create_dir_all(&args.evidence)?;
    for (name, case) in cases() {
        if args.selection == "all" || args.selection == name {
            exchange(&args, name, &case)?;
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("application examples: {error}");
        std::process::exit(1);
    }
}
