use regex::Regex;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use toml::Value;

#[cfg(test)]
mod tests;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const CORE_URL: &str = "https://github.com/hibanaworks/hibana";
const TLS_URL: &str = "https://github.com/hibanaworks/hibana-tls";
const IGNORED: &[&str] = &[".git", "__pycache__", ".ci-work", "ci-safe-results"];
const STAGE_IGNORED: &[&str] = &[
    ".git",
    "target",
    "__pycache__",
    ".ci-work",
    "ci-safe-results",
    "node_modules",
];

pub struct Identity {
    pub tls_revision: String,
    pub core_revision: String,
    pub core_version: String,
}

fn read_toml(path: &Path) -> Result<Value> {
    Ok(toml::from_str(&fs::read_to_string(path)?)?)
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string {key}").into())
}

fn revision(dependency: &Value, repository: &str) -> Result<String> {
    if string(dependency, "git")? != repository {
        return Err(format!("wrong repository for {repository}").into());
    }
    let revision = string(dependency, "rev")?;
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(format!("{repository} requires a full immutable Git commit").into());
    }
    Ok(revision.into())
}

impl Identity {
    pub fn read(root: &Path) -> Result<Self> {
        let manifest = read_toml(&root.join("Cargo.toml"))?;
        if manifest
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            != Some("hibana-quic")
        {
            return Err("wrong QUIC package".into());
        }
        let dependencies = manifest.get("dependencies").ok_or("missing dependencies")?;
        let core = dependencies
            .get("hibana")
            .ok_or("missing Hibana dependency")?;
        let tls = dependencies
            .get("hibana-tls")
            .ok_or("missing TLS dependency")?;
        let core_revision = revision(core, CORE_URL)?;
        let tls_revision = revision(tls, TLS_URL)?;
        let version = string(core, "version")?
            .strip_prefix('=')
            .filter(|v| !v.is_empty())
            .ok_or("Hibana requires an exact version")?;
        let source = manifest
            .get("package")
            .and_then(|p| p.get("metadata"))
            .and_then(|m| m.get("hibana-source"))
            .ok_or("missing Hibana source metadata")?;
        if string(source, "repository")? != CORE_URL
            || string(source, "revision")? != core_revision
            || string(source, "version")? != version
        {
            return Err("Hibana source metadata differs from its dependency".into());
        }
        let identity = Self {
            tls_revision,
            core_revision,
            core_version: version.into(),
        };
        identity.check_core(core)?;
        identity.check_lock(&root.join("Cargo.lock"))?;
        Ok(identity)
    }

    fn check_core(&self, dependency: &Value) -> Result<()> {
        let expected: Value = toml::from_str(&format!(
            "git = {CORE_URL:?}\nrev = {:?}\nversion = {:?}\ndefault-features = false\n",
            self.core_revision,
            format!("={}", self.core_version)
        ))?;
        if *dependency != expected {
            return Err(
                "Hibana dependency differs from the exact no-default-features source".into(),
            );
        }
        Ok(())
    }

    fn check_dependencies_in(&self, value: &Value) -> Result<()> {
        if let Value::Table(table) = value {
            for (key, value) in table {
                if matches!(
                    key.as_str(),
                    "dependencies" | "dev-dependencies" | "build-dependencies"
                ) {
                    if let Some(dependency) = value.get("hibana") {
                        self.check_core(dependency)?;
                    }
                    if let Some(dependency) = value.get("hibana-tls")
                        && (revision(dependency, TLS_URL)? != self.tls_revision
                            || dependency.get("default-features").and_then(Value::as_bool)
                                != Some(false)
                            || dependency.get("path").is_some())
                    {
                        return Err("different TLS dependency".into());
                    }
                } else {
                    self.check_dependencies_in(value)?;
                }
            }
        }
        Ok(())
    }

    fn check_lock(&self, path: &Path) -> Result<()> {
        let lock = read_toml(path)?;
        let packages = lock
            .get("package")
            .and_then(Value::as_array)
            .ok_or("missing lock packages")?;
        let core: Vec<_> = packages
            .iter()
            .filter(|p| p.get("name").and_then(Value::as_str) == Some("hibana"))
            .collect();
        let [core] = core.as_slice() else {
            return Err(
                format!("{} must contain exactly one Hibana package", path.display()).into(),
            );
        };
        let expected = format!("git+{CORE_URL}?rev={0}#{0}", self.core_revision);
        if string(core, "version")? != self.core_version
            || string(core, "source")? != expected
            || core.get("checksum").is_some()
        {
            return Err(format!("{} resolves a different Hibana identity", path.display()).into());
        }
        Ok(())
    }
}

fn files(root: &Path, ignored: &[&str]) -> Result<Vec<PathBuf>> {
    fn visit(directory: &Path, ignored: &[&str], output: &mut Vec<PathBuf>) -> Result<()> {
        let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if ignored.iter().any(|name| entry.file_name() == *name) {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                return Err(
                    format!("source symlink not admitted: {}", entry.path().display()).into(),
                );
            }
            if kind.is_dir() {
                visit(&entry.path(), ignored, output)?;
            } else if kind.is_file() {
                output.push(entry.path());
            } else {
                return Err(format!("non-regular source: {}", entry.path().display()).into());
            }
        }
        Ok(())
    }
    let mut output = Vec::new();
    visit(root, ignored, &mut output)?;
    Ok(output)
}

fn hash(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

struct SourceAudit {
    key: Regex,
    credential: Regex,
    keylog: Regex,
}

impl SourceAudit {
    fn new() -> Result<Self> {
        Ok(Self {
            key: Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*\n[A-Za-z0-9+/]{24,}")?,
            credential: Regex::new(
                r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b",
            )?,
            keylog: Regex::new(
                r"(?m)^(?:CLIENT_RANDOM|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0)\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s*$",
            )?,
        })
    }

    fn check(&self, relative: &Path, data: &[u8]) -> Result<()> {
        let name = relative.to_str().ok_or("non-UTF-8 source path")?;
        if relative.components().any(|p| {
            matches!(
                p.as_os_str().to_str(),
                Some("target" | "inputs" | "node_modules")
            )
        }) {
            return Err(format!("private/generated input directory: {name}").into());
        }
        let extension = relative.extension().and_then(|s| s.to_str()).unwrap_or("");
        if matches!(
            extension.to_ascii_lowercase().as_str(),
            "key" | "pem" | "p12" | "pfx" | "pk8" | "pcap" | "pcapng" | "qlog" | "pyc"
        ) {
            return Err(format!("private fixture/raw/generated artifact: {name}").into());
        }
        let public_vector = (name.starts_with("tests/vectors/")
            && matches!(extension, "bin" | "der" | "sig"))
            || (name.starts_with("vendor/rustls-webpki-0.103.15/src/data/") && extension == "der");
        if !public_vector {
            let text = std::str::from_utf8(data)?;
            if self.key.is_match(text)
                || self.credential.is_match(text)
                || self.keylog.is_match(text)
            {
                return Err(
                    format!("private key, credential or TLS key log in source: {name}").into(),
                );
            }
        }
        Ok(())
    }
}

pub fn audit_pair(root: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    let tls = root
        .parent()
        .ok_or("source has no parent")?
        .join("hibana-tls")
        .canonicalize()?;
    let audit = SourceAudit::new()?;
    for root in [&root, &tls] {
        let files = files(root, IGNORED)?;
        for path in &files {
            audit.check(path.strip_prefix(root)?, &fs::read(path)?)?;
        }
        println!("source audit: {} files in {}", files.len(), root.display());
    }
    Ok(())
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn check_paths(value: &Value, base: &Path, roots: &[(&Path, &str)]) -> Result<()> {
    match value {
        Value::Table(table) => {
            for (key, value) in table {
                if key == "path" {
                    let path = value.as_str().ok_or("non-string Cargo path")?;
                    let resolved = base.join(path).canonicalize()?;
                    if Path::new(path).is_absolute()
                        || !roots.iter().any(|(root, _)| resolved.starts_with(root))
                    {
                        return Err(format!(
                            "Cargo path outside the relocatable source pair: {path}"
                        )
                        .into());
                    }
                } else {
                    check_paths(value, base, roots)?;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                check_paths(value, base, roots)?;
            }
        }
        _ => (),
    }
    Ok(())
}

pub fn check_dependencies(root: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    let identity = Identity::read(&root)?;
    let pins = fs::read_to_string(root.join("tools/ci/pins.env"))?;
    let pins: BTreeMap<_, _> = pins
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_once('=').ok_or("invalid pin row"))
        .collect::<std::result::Result<_, _>>()?;
    for (key, expected) in [
        ("HIBANA_VERSION", &identity.core_version),
        ("HIBANA_REVISION", &identity.core_revision),
        ("HIBANA_TLS_REVISION", &identity.tls_revision),
    ] {
        if pins.get(key).copied() != Some(expected.as_str()) {
            return Err(format!("{key} differs from the dependency identity").into());
        }
    }
    let manifests = [
        "Cargo.toml",
        "pal/Cargo.toml",
        "examples/Cargo.toml",
        "tests/interop/driver/Cargo.toml",
        "tests/tls-reference/Cargo.toml",
        "pal/examples/pico/Cargo.toml",
    ];
    let eliminated = [
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
    let local = [
        "hibana",
        "hibana-quic",
        "hibana-tls",
        "hibana-quic-pal",
        "actor-test-allocator",
        "hibana-quic-pico-example",
        "hibana-quic-examples",
        "hibana-quic-interop",
    ];
    let test_runtime = [
        "tokio",
        "tokio-macros",
        "pin-project-lite",
        "proc-macro2",
        "quote",
        "syn",
        "unicode-ident",
    ];
    let tls_source = format!("git+{TLS_URL}?rev={0}#{0}", identity.tls_revision);
    for relative in manifests {
        let path = root.join(relative);
        let manifest = read_toml(&path)?;
        identity.check_dependencies_in(&manifest)?;
        if manifest
            .get("patch")
            .and_then(Value::as_table)
            .is_some_and(|patch| {
                patch.values().any(|entries| {
                    entries.get("hibana").is_some() || entries.get("hibana-tls").is_some()
                })
            })
        {
            return Err(format!("{relative} overrides an immutable dependency").into());
        }
        let lock_path = path.with_file_name("Cargo.lock");
        identity.check_lock(&lock_path)?;
        let lock = read_toml(&lock_path)?;
        let packages = lock
            .get("package")
            .and_then(Value::as_array)
            .ok_or("missing lock packages")?;
        let tls: Vec<_> = packages
            .iter()
            .filter(|p| p.get("name").and_then(Value::as_str) == Some("hibana-tls"))
            .collect();
        let [tls] = tls.as_slice() else {
            return Err(format!("{relative} must resolve one TLS identity").into());
        };
        if string(tls, "source")? != tls_source {
            return Err(format!("{relative} resolves a different TLS identity").into());
        }
        let reference = relative == "tests/tls-reference/Cargo.toml";
        for package in packages {
            let name = string(package, "name")?;
            if eliminated.contains(&name)
                || (!reference
                    && !local.contains(&name)
                    && !(relative == "Cargo.toml" && test_runtime.contains(&name)))
            {
                return Err(format!("unexpected package {name} in {relative}").into());
            }
        }
        if !reference {
            let tree = Command::new("cargo")
                .args(["tree", "--locked", "--manifest-path"])
                .arg(&path)
                .args(["-e", "normal,build", "--prefix", "none"])
                .output()?;
            if !tree.status.success() {
                return Err(format!(
                    "cargo tree failed for {relative}: {}",
                    String::from_utf8_lossy(&tree.stderr)
                )
                .into());
            }
            for line in std::str::from_utf8(&tree.stdout)?.lines() {
                let name = line
                    .split_whitespace()
                    .next()
                    .ok_or("empty dependency row")?;
                if !local.contains(&name) || name == "actor-test-allocator" {
                    return Err(
                        format!("unexpected production dependency {name} in {relative}").into(),
                    );
                }
            }
        }
    }
    let tls = root
        .parent()
        .ok_or("source has no parent")?
        .join("hibana-tls")
        .canonicalize()?;
    let manifest = read_toml(&tls.join("Cargo.toml"))?;
    identity.check_core(
        manifest
            .get("dependencies")
            .and_then(|d| d.get("hibana"))
            .ok_or("TLS has no Hibana dependency")?,
    )?;
    if manifest
        .get("patch")
        .and_then(Value::as_table)
        .is_some_and(|patch| {
            patch
                .values()
                .any(|entries| entries.get("hibana").is_some())
        })
    {
        return Err("TLS overrides its Hibana dependency".into());
    }
    identity.check_lock(&tls.join("Cargo.lock"))?;
    if root.join("vendor/rustls-webpki-0.103.15").exists()
        || tls.join("vendor/rustls-webpki-0.103.15").exists()
    {
        return Err("unqualified crypto vendor copy".into());
    }
    println!("exact Hibana/TLS identities and production dependency closures verified");
    Ok(())
}

pub fn stage(root: &Path, output: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    let identity = Identity::read(&root)?;
    let tls = root
        .parent()
        .ok_or("source has no parent")?
        .join("hibana-tls")
        .canonicalize()?;
    if git(&tls, &["rev-parse", "HEAD"])?.trim() != identity.tls_revision {
        return Err("sibling TLS checkout differs from the dependency revision".into());
    }
    if !git(&tls, &["status", "--porcelain", "--untracked-files=all"])?.is_empty() {
        return Err("TLS checkout must be clean".into());
    }
    let tls_manifest = read_toml(&tls.join("Cargo.toml"))?;
    if tls_manifest
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        != Some("hibana-tls")
    {
        return Err("wrong sibling TLS package".into());
    }
    identity.check_core(
        tls_manifest
            .get("dependencies")
            .and_then(|d| d.get("hibana"))
            .ok_or("TLS has no Hibana dependency")?,
    )?;
    identity.check_lock(&tls.join("Cargo.lock"))?;
    if output.exists() && fs::read_dir(output)?.next().is_some() {
        return Err("output must be new or empty".into());
    }
    let roots = [
        (root.as_path(), "hibana-quic"),
        (tls.as_path(), "hibana-tls"),
    ];
    let audit = SourceAudit::new()?;
    let mut contents = Vec::new();
    let mut entries = BTreeMap::new();
    for (root, name) in roots {
        for source in files(root, STAGE_IGNORED)? {
            let relative = source.strip_prefix(root)?;
            let data = fs::read(&source)?;
            audit.check(relative, &data)?;
            if source.file_name().is_some_and(|name| name == "Cargo.toml") {
                check_paths(
                    &read_toml(&source)?,
                    source.parent().ok_or("manifest has no parent")?,
                    &roots,
                )?;
            }
            let destination = Path::new(name).join(relative);
            entries.insert(
                destination
                    .to_str()
                    .ok_or("non-UTF-8 source path")?
                    .to_owned(),
                hash(&data),
            );
            contents.push((destination, data));
        }
    }
    let mut trees = BTreeMap::new();
    for (_, name) in roots {
        let subset: BTreeMap<_, _> = entries
            .iter()
            .filter(|(path, _)| path.starts_with(&format!("{name}/")))
            .collect();
        trees.insert(name, hash(&serde_json::to_vec(&subset)?));
    }
    fs::create_dir_all(output)?;
    for (destination, data) in contents {
        let destination = output.join(destination);
        fs::create_dir_all(destination.parent().ok_or("destination has no parent")?)?;
        fs::write(destination, data)?;
    }
    fs::write(
        output.join("source-files.json"),
        serde_json::to_vec_pretty(&entries)?,
    )?;
    fs::write(
        output.join("source-pair.json"),
        serde_json::to_vec_pretty(&json!({
            "inventory_format": 1, "trees": trees, "file_count": entries.len(),
            "tls_repository": TLS_URL, "tls_revision": identity.tls_revision,
            "hibana_version": identity.core_version, "hibana_revision": identity.core_revision,
        }))?,
    )?;
    println!(
        "{}",
        json!({ "output": output, "trees": trees, "files": entries.len() })
    );
    Ok(())
}
