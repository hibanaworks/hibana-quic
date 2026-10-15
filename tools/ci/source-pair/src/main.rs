use regex::Regex;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const CORE_REPOSITORY: &str = "https://github.com/hibanaworks/hibana";
const TLS_REPOSITORY: &str = "https://github.com/hibanaworks/hibana-tls";
const SKIP: &[&str] = &[
    ".git",
    "target",
    "__pycache__",
    ".ci-work",
    "ci-safe-results",
    "node_modules",
];

fn require(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message.into()).into())
    }
}

fn parse(path: &Path) -> Result<toml::Value> {
    let text = fs::read_to_string(path)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?;
    Ok(text.parse()?)
}

fn field<'a>(value: &'a toml::Value, path: &[&str]) -> Result<&'a toml::Value> {
    let mut value = value;
    for name in path {
        value = value
            .get(name)
            .ok_or_else(|| io::Error::other(format!("missing field {}", path.join("."))))?;
    }
    Ok(value)
}

fn string(value: &toml::Value) -> Result<&str> {
    value
        .as_str()
        .ok_or_else(|| io::Error::other("expected a string").into())
}

fn revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn git(folder: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(folder)
        .args(args)
        .output()?;
    require(output.status.success(), "Git source inspection failed")?;
    Ok(String::from_utf8(output.stdout)?)
}

fn files(folder: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = fs::read_dir(folder)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if SKIP.iter().any(|name| entry.file_name() == *name) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        require(
            !metadata.is_symlink(),
            format!("source symlink: {}", path.display()),
        )?;
        if metadata.is_dir() {
            files(&path, output)?;
        } else {
            require(metadata.is_file(), "source must be a regular file")?;
            output.push(path);
        }
    }
    Ok(())
}

fn core_package(lock: &toml::Value) -> Result<Vec<&toml::Value>> {
    let packages = field(lock, &["package"])?
        .as_array()
        .ok_or_else(|| io::Error::other("lockfile package list is missing"))?;
    Ok(packages
        .iter()
        .filter(|package| package.get("name").and_then(toml::Value::as_str) == Some("hibana"))
        .collect())
}

fn check_lock(lock: &toml::Value, version: &str, source: &str) -> Result<()> {
    let selected = core_package(lock)?;
    require(selected.len() == 1, "one exact Hibana identity is required")?;
    require(
        selected[0].get("source").and_then(toml::Value::as_str) == Some(source)
            && selected[0].get("version").and_then(toml::Value::as_str) == Some(version),
        "consumer lock selected a different core",
    )
}

fn check_patch(manifest: &toml::Value, core_revision: &str) -> Result<()> {
    let patch = field(manifest, &["patch", "crates-io", "hibana"])?;
    require(
        patch.as_table().is_some_and(|table| table.len() == 2)
            && patch.get("git").and_then(toml::Value::as_str) == Some(CORE_REPOSITORY)
            && patch.get("rev").and_then(toml::Value::as_str) == Some(core_revision),
        "consumer patch differs from the core pin",
    )
}

fn consumes_core(manifest: &toml::Value) -> bool {
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(dependencies) = manifest.get(section).and_then(toml::Value::as_table)
            && dependencies.iter().any(|(name, dependency)| {
                matches!(name.as_str(), "hibana" | "hibana-tls")
                    || dependency
                        .get("package")
                        .and_then(toml::Value::as_str)
                        .is_some_and(|name| matches!(name, "hibana" | "hibana-tls"))
            })
        {
            return true;
        }
    }
    manifest
        .get("target")
        .and_then(toml::Value::as_table)
        .is_some_and(|targets| targets.values().any(consumes_core))
}

fn output_path(path: &Path) -> Result<PathBuf> {
    let path = std::path::absolute(path)?;
    require(
        !path
            .components()
            .any(|component| component == std::path::Component::ParentDir),
        "output path must not contain a parent traversal",
    )?;
    if path.exists() {
        return Ok(path.canonicalize()?);
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("output has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("output has no name"))?;
    Ok(output_path(parent)?.join(name))
}

fn path_key(path: &Path) -> Result<String> {
    path.iter()
        .map(|part| {
            part.to_str()
                .ok_or_else(|| io::Error::other("source path is not UTF-8").into())
        })
        .collect::<Result<Vec<_>>>()
        .map(|parts| parts.join("/"))
}

fn relative_path(from: &Path, to: &Path) -> Result<String> {
    let from: Vec<_> = from.components().collect();
    let to: Vec<_> = to.components().collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut result = PathBuf::new();
    for _ in common..from.len() {
        result.push("..");
    }
    for component in &to[common..] {
        result.push(component.as_os_str());
    }
    if result.as_os_str().is_empty() {
        result.push(".");
    }
    path_key(&result)
}

fn normalize_manifest(
    data: &[u8],
    source: &Path,
    destination: &Path,
    roots: &[(&Path, &str)],
    output: &Path,
    pattern: &Regex,
) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(data)?;
    let mut normalized = String::new();
    let mut end = 0;
    for captures in pattern.captures_iter(text) {
        let matched = captures
            .get(0)
            .ok_or_else(|| io::Error::other("missing path match"))?;
        let dependency_path = source
            .parent()
            .ok_or_else(|| io::Error::other("manifest has no parent"))?
            .join(&captures[1]);
        let dependency = dependency_path.canonicalize().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("{}: {error}", dependency_path.display()),
            )
        })?;
        let mut mapped = None;
        for (origin, name) in roots {
            if let Ok(relative) = dependency.strip_prefix(origin) {
                mapped = Some(output.join(name).join(relative));
                break;
            }
        }
        let mapped = mapped.ok_or_else(|| io::Error::other("path is outside the paired source"))?;
        let parent = destination
            .parent()
            .ok_or_else(|| io::Error::other("missing output parent"))?;
        normalized.push_str(&text[end..matched.start()]);
        normalized.push_str("path = ");
        normalized.push_str(&serde_json::to_string(&relative_path(parent, &mapped)?)?);
        end = matched.end();
    }
    normalized.push_str(&text[end..]);
    Ok(normalized.into_bytes())
}

// Preserve the existing public tree-digest format: sorted JSON string pairs,
// ASCII escapes, and one space after commas and colons.
fn digest_json_string(value: &str) -> Result<String> {
    let encoded = serde_json::to_string(value)?;
    let mut escaped = String::new();
    for character in encoded.chars() {
        if (character as u32) < 127 {
            escaped.push(character);
        } else {
            let mut units = [0; 2];
            for unit in character.encode_utf16(&mut units) {
                escaped.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    Ok(escaped)
}

fn tree_digest(entries: &BTreeMap<String, String>, name: &str) -> Result<String> {
    let prefix = format!("{name}/");
    let mut pairs = Vec::new();
    for (path, hash) in entries {
        if path.starts_with(&prefix) {
            pairs.push(format!(
                "{}: {}",
                digest_json_string(path)?,
                digest_json_string(hash)?
            ));
        }
    }
    Ok(format!(
        "{:x}",
        Sha256::digest(format!("{{{}}}", pairs.join(", ")))
    ))
}

fn stage(root: &Path, requested_output: &Path) -> Result<serde_json::Value> {
    let root = root.canonicalize()?;
    let manifest = parse(&root.join("Cargo.toml"))?;
    let identity = field(&manifest, &["package", "metadata", "hibana-source"])?;
    require(
        string(field(identity, &["repository"])?)? == CORE_REPOSITORY,
        "unexpected core repository",
    )?;
    let core_revision = string(field(identity, &["revision"])?)?;
    let core_version = string(field(identity, &["version"])?)?;
    require(revision(core_revision), "core requires an immutable commit")?;
    let core_source = format!("git+{CORE_REPOSITORY}?rev={core_revision}#{core_revision}");
    check_lock(
        &parse(&root.join("Cargo.lock"))?,
        core_version,
        &core_source,
    )?;
    let pins: BTreeMap<_, _> = fs::read_to_string(root.join("tools/ci/pins.env"))?
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            line.split_once('=')
                .map(|(a, b)| (a.to_owned(), b.to_owned()))
        })
        .collect::<Option<_>>()
        .ok_or_else(|| io::Error::other("invalid source pin"))?;
    require(
        pins.get("HIBANA_VERSION").map(String::as_str) == Some(core_version)
            && pins.get("HIBANA_REVISION").map(String::as_str) == Some(core_revision),
        "source pins disagree with the lock",
    )?;
    let mut quic_files = Vec::new();
    files(&root, &mut quic_files)?;
    for path in &quic_files {
        if path.file_name().is_some_and(|name| name == "Cargo.lock") {
            let lock = parse(path)?;
            let consumer = parse(&path.with_file_name("Cargo.toml"))?;
            let patch = consumer
                .get("patch")
                .and_then(|p| p.get("crates-io"))
                .and_then(|p| p.get("hibana"));
            // Host-only CI tools do not consume Hibana. A core-bearing lock or
            // declared core patch must pass the exact same identity checks.
            if !core_package(&lock)?.is_empty() || patch.is_some() || consumes_core(&consumer) {
                check_lock(&lock, core_version, &core_source)?;
                check_patch(&consumer, core_revision)?;
            }
        }
    }
    let tls = root
        .parent()
        .ok_or_else(|| io::Error::other("missing paired source parent"))?
        .join("hibana-tls")
        .canonicalize()?;
    let dependency = field(&manifest, &["dependencies", "hibana-tls"])?;
    let tls_revision = string(field(dependency, &["rev"])?)?;
    require(
        revision(tls_revision) && string(field(dependency, &["git"])?)? == TLS_REPOSITORY,
        "TLS requires an immutable owned source",
    )?;
    require(
        git(&tls, &["rev-parse", "HEAD"])?.trim() == tls_revision,
        "sibling TLS checkout differs from its dependency",
    )?;
    require(
        git(&tls, &["status", "--porcelain", "--untracked-files=all"])?.is_empty(),
        "TLS checkout must be clean",
    )?;
    require(
        string(field(
            &parse(&tls.join("Cargo.toml"))?,
            &["package", "name"],
        )?)? == "hibana-tls",
        "unexpected TLS package",
    )?;
    let mut tls_files = Vec::new();
    files(&tls, &mut tls_files)?;
    if requested_output.exists() {
        require(
            fs::read_dir(requested_output)?.next().is_none(),
            "output must be new or empty",
        )?;
    }
    let output = output_path(requested_output)?;
    require(
        !output.starts_with(&root) || output.starts_with(root.join(".ci-work")),
        "output must not enter source inventory",
    )?;
    require(
        !output.starts_with(&tls),
        "output must not enter TLS source",
    )?;
    let roots = [
        (root.as_path(), "hibana-quic"),
        (tls.as_path(), "hibana-tls"),
    ];
    let pattern = Regex::new(r#"\bpath\s*=\s*"([^"\n]+)""#)?;
    let mut entries = BTreeMap::new();
    let mut contents = Vec::new();
    for ((origin, name), paths) in roots.iter().zip([quic_files, tls_files]) {
        for source in paths {
            let relative = source.strip_prefix(origin)?;
            let destination = output.join(name).join(relative);
            let mut data = fs::read(&source)?;
            if source.file_name().is_some_and(|name| name == "Cargo.toml") {
                data = normalize_manifest(&data, &source, &destination, &roots, &output, &pattern)?;
            }
            entries.insert(
                path_key(destination.strip_prefix(&output)?)?,
                format!("{:x}", Sha256::digest(&data)),
            );
            contents.push((destination, data));
        }
    }
    fs::create_dir_all(&output)?;
    for (destination, data) in contents {
        fs::create_dir_all(
            destination
                .parent()
                .ok_or_else(|| io::Error::other("missing destination parent"))?,
        )?;
        fs::write(destination, data)?;
    }
    let trees = BTreeMap::from([
        ("hibana-quic", tree_digest(&entries, "hibana-quic")?),
        ("hibana-tls", tree_digest(&entries, "hibana-tls")?),
    ]);
    let pair = json!({
        "trees": trees, "file_count": entries.len(), "tls_repository": TLS_REPOSITORY,
        "tls_revision": tls_revision, "hibana_version": core_version, "hibana_revision": core_revision
    });
    fs::write(
        output.join("source-files.json"),
        serde_json::to_string_pretty(&entries)? + "\n",
    )?;
    fs::write(
        output.join("source-pair.json"),
        serde_json::to_string_pretty(&pair)? + "\n",
    )?;
    Ok(json!({"output": output, "trees": trees, "files": entries.len()}))
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    require(
        args.len() == 2 && args[0] == "--output",
        "usage: stage-paired-source --output DIRECTORY",
    )?;
    let result = stage(&std::env::current_dir()?, &PathBuf::from(&args[1]))?;
    println!("{result}");
    Ok(())
}
