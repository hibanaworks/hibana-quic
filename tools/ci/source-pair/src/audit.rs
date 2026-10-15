use super::{
    CORE_REPOSITORY, Result, TLS_REPOSITORY, check_lock, check_patch, field, parse, require,
    revision, string,
};
use regex::Regex;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
};

const CONSUMERS: &[&str] = &[
    "Cargo.toml",
    "pal/Cargo.toml",
    "examples/Cargo.toml",
    "tests/interop/driver/Cargo.toml",
    "tests/tls-reference/Cargo.toml",
    "pal/examples/pico/Cargo.toml",
];
const OWNED: &[&str] = &[
    "hibana",
    "hibana-quic",
    "hibana-tls",
    "hibana-quic-pal",
    "hibana-quic-pico-example",
    "hibana-quic-examples",
    "hibana-quic-interop",
];
const NORMAL_OWNED: &[&str] = &[
    "hibana",
    "hibana-quic",
    "hibana-tls",
    "hibana-quic-pal",
    "hibana-quic-examples",
    "hibana-quic-interop",
];
const ELIMINATED: &[&str] = &[
    "hkdf",
    "pkcs1",
    "chacha20",
    "chacha20poly1305",
    "poly1305",
    "aes",
    "aes-gcm",
    "ghash",
    "polyval",
    "ctr",
    "cipher",
    "inout",
    "aead",
    "universal-hash",
    "opaque-debug",
    "x25519-dalek",
    "curve25519-dalek",
    "curve25519-dalek-derive",
    "fiat-crypto",
    "ff",
    "primeorder",
    "signature",
    "spki",
    "base16ct",
    "elliptic-curve",
    "const-oid",
    "rfc6979",
    "sec1",
    "pkcs8",
    "group",
    "hmac",
    "p256",
    "ecdsa",
    "crypto-common",
    "version_check",
    "cpufeatures",
    "typenum",
    "digest",
    "generic-array",
    "block-buffer",
    "sha2",
    "crypto-bigint",
    "rand_core",
];

pub(super) fn pins(root: &Path) -> Result<BTreeMap<String, String>> {
    fs::read_to_string(root.join("tools/ci/pins.env"))?
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            line.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
        })
        .collect::<Option<_>>()
        .ok_or_else(|| std::io::Error::other("invalid source pin").into())
}

pub(super) fn tls_revision(root: &Path) -> Result<String> {
    let manifest = parse(&root.join("Cargo.toml"))?;
    let dependency = field(&manifest, &["dependencies", "hibana-tls"])?;
    let value = string(field(dependency, &["rev"])?)?;
    require(
        revision(value) && string(field(dependency, &["git"])?)? == TLS_REPOSITORY,
        "TLS requires an immutable owned source",
    )?;
    Ok(value.to_owned())
}

fn content(path: &Path, data: &[u8], patterns: &[Regex]) -> Result<()> {
    let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    require(
        ![
            "key", "pem", "p12", "pfx", "pk8", "pcap", "pcapng", "qlog", "pyc",
        ]
        .contains(&extension.to_ascii_lowercase().as_str()),
        "private or generated artifact in source",
    )?;
    let public_vector =
        path.starts_with("tests/vectors") && ["bin", "der", "sig"].contains(&extension);
    if !public_vector {
        let text = std::str::from_utf8(data)?;
        for pattern in patterns {
            require(!pattern.is_match(text), "private material in source")?;
        }
    }
    Ok(())
}

fn source_files(root: &Path, folder: &Path, patterns: &[Regex]) -> Result<usize> {
    let mut count = 0;
    for entry in fs::read_dir(folder)? {
        let entry = entry?;
        let name = entry.file_name();
        if [".git", "__pycache__", ".ci-work", "ci-safe-results"]
            .iter()
            .any(|s| name == *s)
        {
            continue;
        }
        require(
            !["target", "inputs", "node_modules"]
                .iter()
                .any(|s| name == *s),
            "generated input directory in source",
        )?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        require(!metadata.is_symlink(), "source symlink is not admitted")?;
        if metadata.is_dir() {
            count += source_files(root, &path, patterns)?;
        } else {
            require(metadata.is_file(), "source must be a regular file")?;
            content(path.strip_prefix(root)?, &fs::read(&path)?, patterns)?;
            count += 1;
        }
    }
    Ok(count)
}

fn patterns() -> Result<Vec<Regex>> {
    [
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*\n[A-Za-z0-9+/]{24,}",
        r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b",
        r"(?m)^(?:CLIENT_RANDOM|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0)\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s*$",
    ].iter().map(|p| Ok(Regex::new(p)?)).collect()
}

pub(super) fn sources(root: &Path) -> Result<()> {
    let tls = root
        .parent()
        .ok_or("missing TLS parent")?
        .join("hibana-tls");
    let patterns = patterns()?;
    let quic_count = source_files(root, root, &patterns)?;
    let tls_count = source_files(&tls, &tls, &patterns)?;
    println!("Source audit passed: {quic_count} QUIC and {tls_count} TLS files");
    Ok(())
}

fn packages(lock: &toml::Value) -> Result<&Vec<toml::Value>> {
    field(lock, &["package"])?
        .as_array()
        .ok_or_else(|| "missing lock packages".into())
}

fn package<'a>(lock: &'a toml::Value, name: &str) -> Result<&'a toml::Value> {
    let matches: Vec<_> = packages(lock)?
        .iter()
        .filter(|p| p.get("name").and_then(toml::Value::as_str) == Some(name))
        .collect();
    require(matches.len() == 1, "one exact package identity is required")?;
    Ok(matches[0])
}

fn core_dependency(manifest: &toml::Value, version: &str) -> Result<()> {
    let dependency = manifest
        .get("dependencies")
        .and_then(|d| d.get("hibana"))
        .or_else(|| {
            manifest
                .get("dev-dependencies")
                .and_then(|d| d.get("hibana"))
        });
    if let Some(dependency) = dependency {
        require(
            dependency.as_table().is_some_and(|t| t.len() == 2)
                && dependency.get("version").and_then(toml::Value::as_str)
                    == Some(format!("={version}").as_str())
                && dependency
                    .get("default-features")
                    .and_then(toml::Value::as_bool)
                    == Some(false),
            "unexpected core dependency",
        )?;
    }
    Ok(())
}

fn allowed_packages(lock: &toml::Value, reference: bool) -> Result<()> {
    for package in packages(lock)? {
        let name = string(field(package, &["name"])?)?;
        require(
            !ELIMINATED.contains(&name),
            "eliminated dependency returned",
        )?;
        if !reference {
            require(
                OWNED.contains(&name) || name == "actor-test-allocator",
                "foreign runtime dependency",
            )?;
        }
    }
    Ok(())
}

pub(super) fn dependencies(root: &Path) -> Result<()> {
    let pins = pins(root)?;
    let value = |key: &str| {
        pins.get(key)
            .map(String::as_str)
            .ok_or_else(|| std::io::Error::other(format!("missing pin {key}")))
    };
    let version = value("HIBANA_VERSION")?;
    let core_rev = value("HIBANA_REVISION")?;
    let checksum = value("HIBANA_CHECKSUM")?;
    let tls_rev = tls_revision(root)?;
    require(
        revision(core_rev) && value("HIBANA_TLS_REVISION")? == tls_rev,
        "source pin mismatch",
    )?;
    require(
        checksum.len() == 64
            && checksum
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid published checksum",
    )?;
    let source = format!("git+{CORE_REPOSITORY}?rev={core_rev}#{core_rev}");
    let tls_source = format!("git+{TLS_REPOSITORY}?rev={tls_rev}#{tls_rev}");
    for relative in CONSUMERS {
        let path = root.join(relative);
        let manifest = parse(&path)?;
        let lock = parse(&path.with_file_name("Cargo.lock"))?;
        core_dependency(&manifest, version)?;
        check_patch(&manifest, core_rev)?;
        require(
            manifest
                .get("patch")
                .and_then(toml::Value::as_table)
                .is_some_and(|p| p.len() == 1)
                && field(&manifest, &["patch", "crates-io"])?
                    .as_table()
                    .is_some_and(|p| p.len() == 1),
            "unexpected dependency override",
        )?;
        check_lock(&lock, version, &source)?;
        require(
            package(&lock, "hibana")?.get("checksum").is_none(),
            "Git core cannot carry a registry checksum",
        )?;
        allowed_packages(&lock, relative.contains("tls-reference"))?;
        require(
            string(field(package(&lock, "hibana-tls")?, &["source"])?)? == tls_source,
            "TLS lock identity differs",
        )?;
        for section in ["dependencies", "dev-dependencies"] {
            if let Some(dependency) = manifest.get(section).and_then(|d| d.get("hibana-tls")) {
                require(
                    dependency.get("git").and_then(toml::Value::as_str) == Some(TLS_REPOSITORY)
                        && dependency.get("rev").and_then(toml::Value::as_str)
                            == Some(tls_rev.as_str())
                        && dependency
                            .get("default-features")
                            .and_then(toml::Value::as_bool)
                            == Some(false)
                        && dependency.get("path").is_none(),
                    "unexpected TLS dependency",
                )?;
            }
        }
        if [
            "Cargo.toml",
            "pal/Cargo.toml",
            "examples/Cargo.toml",
            "tests/interop/driver/Cargo.toml",
        ]
        .contains(relative)
        {
            let output = Command::new("cargo")
                .args(["+1.95.0", "tree", "--locked", "--manifest-path"])
                .arg(&path)
                .args(["-e", "normal,build", "--prefix", "none"])
                .output()?;
            require(output.status.success(), "cargo tree failed")?;
            let text = String::from_utf8(output.stdout)?;
            let names: BTreeSet<_> = text
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .collect();
            require(
                names.iter().all(|name| NORMAL_OWNED.contains(name)),
                "foreign normal/build dependency",
            )?;
        }
    }
    let tls = root
        .parent()
        .ok_or("missing TLS parent")?
        .join("hibana-tls");
    for folder in [root, tls.as_path()] {
        require(
            !folder.join("vendor/rustls-webpki-0.103.15").exists(),
            "removed vendor copy returned",
        )?;
    }
    let manifest = parse(&tls.join("Cargo.toml"))?;
    let _ = field(&manifest, &["dependencies", "hibana"])?;
    core_dependency(&manifest, version)?;
    if let Some(patches) = manifest.get("patch").and_then(toml::Value::as_table) {
        require(
            patches.values().all(|p| p.get("hibana").is_none()),
            "TLS standalone core override",
        )?;
    }
    let lock = parse(&tls.join("Cargo.lock"))?;
    let core = package(&lock, "hibana")?;
    require(
        core.get("version").and_then(toml::Value::as_str) == Some(version)
            && core.get("source").and_then(toml::Value::as_str)
                == Some("registry+https://github.com/rust-lang/crates.io-index")
            && core.get("checksum").and_then(toml::Value::as_str) == Some(checksum),
        "TLS standalone published core differs",
    )?;
    println!("Exact dependency identities and owned normal/build closures passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_material_and_non_public_binary_are_rejected() {
        let patterns = patterns().unwrap();
        for bytes in [
            b"-----BEGIN PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_slice(),
            b"CLIENT_RANDOM abcd 0123456789".as_slice(),
            b"\xff\x00".as_slice(),
        ] {
            assert!(content(Path::new("src/input.rs"), bytes, &patterns).is_err());
        }
        let token = [b"ghp_".as_slice(), b"abcdefghijklmnopqrstuvwxyz012345"].concat();
        assert!(content(Path::new("src/input.rs"), &token, &patterns).is_err());
        assert!(content(Path::new("tests/vectors/hello.bin"), b"\xff\x00", &patterns).is_ok());
        assert!(content(Path::new("tests/private.pem"), b"public", &patterns).is_err());
    }
    #[test]
    fn reference_dependencies_do_not_enter_runtime_or_restore_eliminated_crypto() {
        let reference: toml::Value = "[[package]]\nname='der'\n".parse().unwrap();
        assert!(allowed_packages(&reference, true).is_ok());
        assert!(allowed_packages(&reference, false).is_err());
        let forbidden: toml::Value = "[[package]]\nname='sha2'\n".parse().unwrap();
        assert!(allowed_packages(&forbidden, true).is_err());
        let own: toml::Value = "[[package]]\nname='hibana-quic'\n".parse().unwrap();
        assert!(allowed_packages(&own, false).is_ok());
    }
}
