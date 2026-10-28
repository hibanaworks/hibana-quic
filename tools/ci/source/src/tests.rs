use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture {
    root: PathBuf,
    revision: String,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "hibana-source-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let quic = root.join("hibana-quic");
        let tls = root.join("hibana-tls");
        fs::create_dir(&quic).unwrap();
        fs::create_dir(&tls).unwrap();
        let core = format!(
            "{{ git = {CORE_URL:?}, rev = {:?}, version = \"=0.10.0\", default-features = false }}",
            "a".repeat(40)
        );
        fs::write(
            tls.join("Cargo.toml"),
            format!("[package]\nname = \"hibana-tls\"\n[dependencies]\nhibana = {core}\n"),
        )
        .unwrap();
        let lock = format!(
            "version = 4\n[[package]]\nname = \"hibana\"\nversion = \"0.10.0\"\nsource = \"git+{CORE_URL}?rev={0}#{0}\"\n",
            "a".repeat(40)
        );
        fs::write(tls.join("Cargo.lock"), &lock).unwrap();
        git(&tls, &["init", "-q"]).unwrap();
        git(&tls, &["add", "."]).unwrap();
        git(
            &tls,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.test",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-qm",
                "Source fixture",
            ],
        )
        .unwrap();
        let revision = git(&tls, &["rev-parse", "HEAD"]).unwrap().trim().to_owned();
        fs::write(quic.join("Cargo.toml"), format!("[package]\nname = \"hibana-quic\"\n[package.metadata.hibana-source]\nrepository = {CORE_URL:?}\nversion = \"0.10.0\"\nrevision = {:?}\n[dependencies]\nhibana = {core}\nhibana-tls = {{git = {TLS_URL:?}, rev = {revision:?}, default-features = false}}\n", "a".repeat(40))).unwrap();
        fs::write(quic.join("Cargo.lock"), lock).unwrap();
        fs::write(quic.join("README.md"), "public source\n").unwrap();
        Self { root, revision }
    }
    fn quic(&self) -> PathBuf {
        self.root.join("hibana-quic")
    }
    fn tls(&self) -> PathBuf {
        self.root.join("hibana-tls")
    }
    fn output(&self) -> PathBuf {
        self.root.join("output")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn stages_exact_clean_git_sources_without_rewriting_manifest_bytes() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.quic().join("target")).unwrap();
    fs::write(fixture.quic().join("target/generated"), "not source").unwrap();
    let before = fs::read(fixture.quic().join("Cargo.toml")).unwrap();
    stage(&fixture.quic(), &fixture.output()).unwrap();
    assert_eq!(
        fs::read(fixture.output().join("hibana-quic/Cargo.toml")).unwrap(),
        before
    );
    assert!(!fixture.output().join("hibana-tls/.git").exists());
    assert!(!fixture.output().join("hibana-quic/target").exists());
    let pair: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.output().join("source-pair.json")).unwrap())
            .unwrap();
    assert_eq!(pair["tls_revision"], fixture.revision);
    assert_eq!(pair["hibana_revision"], "a".repeat(40));
    let entries: BTreeMap<String, String> =
        serde_json::from_slice(&fs::read(fixture.output().join("source-files.json")).unwrap())
            .unwrap();
    assert_eq!(pair["file_count"], entries.len());
    for (path, expected) in entries {
        assert_eq!(
            hash(&fs::read(fixture.output().join(path)).unwrap()),
            expected
        );
    }
    audit_pair(&fixture.output().join("hibana-quic")).unwrap();
    assert!(
        stage(&fixture.quic(), &fixture.output()).is_err(),
        "never mix export attempts"
    );
}

#[test]
fn rejects_a_different_missing_or_dirty_sibling_before_export() {
    for mutation in 0..4 {
        let fixture = Fixture::new();
        match mutation {
            0 => {
                let manifest = fixture.quic().join("Cargo.toml");
                let data = fs::read_to_string(&manifest)
                    .unwrap()
                    .replace(&fixture.revision, &"0".repeat(40));
                fs::write(manifest, data).unwrap();
            }
            1 => fs::write(fixture.tls().join("Cargo.toml"), "modified\n").unwrap(),
            2 => fs::write(fixture.tls().join("extra.rs"), "untracked\n").unwrap(),
            3 => fs::remove_dir_all(fixture.tls()).unwrap(),
            _ => unreachable!(),
        }
        assert!(stage(&fixture.quic(), &fixture.output()).is_err());
        assert!(!fixture.output().exists());
    }
}

#[test]
fn rejects_registry_substitution_metadata_drift_and_default_features() {
    for mutation in 0..3 {
        let fixture = Fixture::new();
        let path = fixture.quic().join(if mutation == 0 {
            "Cargo.lock"
        } else {
            "Cargo.toml"
        });
        let original = fs::read_to_string(&path).unwrap();
        let changed = match mutation {
            0 => original.replace(
                "git+https://github.com/hibanaworks/hibana?",
                "registry+https://github.com/hibanaworks/hibana?",
            ),
            1 => original.replacen("version = \"0.10.0\"", "version = \"0.10.1\"", 1),
            2 => original.replacen("default-features = false", "default-features = true", 1),
            _ => unreachable!(),
        };
        fs::write(path, changed).unwrap();
        assert!(Identity::read(&fixture.quic()).is_err());
    }
}

#[test]
fn rejects_nonrelocatable_cargo_paths() {
    let fixture = Fixture::new();
    let outside = fixture.root.join("outside");
    fs::create_dir(&outside).unwrap();
    let path = fixture.quic().join("Cargo.toml");
    let mut manifest = fs::read_to_string(&path).unwrap();
    manifest.push_str("unqualified = { path = \"../outside\" }\n");
    fs::write(path, manifest).unwrap();
    assert!(stage(&fixture.quic(), &fixture.output()).is_err());
    assert!(!fixture.output().exists());
}

#[test]
fn audits_real_bytes_and_restricts_binary_exceptions_to_public_vectors() {
    let audit = SourceAudit::new().unwrap();
    let token = format!("ghp_{}", "A".repeat(32));
    let key = format!("-----BEGIN {}-----\n{}", "PRIVATE KEY", "A".repeat(32));
    let keylog = format!(
        "{} {} {}\n",
        "CLIENT_RANDOM",
        "a".repeat(32),
        "b".repeat(32)
    );
    for data in [token.as_bytes(), key.as_bytes(), keylog.as_bytes(), &[0xff]] {
        assert!(audit.check(Path::new("source.rs"), data).is_err());
    }
    for name in [
        "inputs/vector.bin",
        "node_modules/code.js",
        "target/code",
        "test.PEM",
        "trace.pcap",
    ] {
        assert!(audit.check(Path::new(name), b"public").is_err());
    }
    assert!(
        audit
            .check(Path::new("tests/vectors/public.bin"), &[0xff])
            .is_ok()
    );
    assert!(audit.check(Path::new("public.bin"), &[0xff]).is_err());
}

#[cfg(unix)]
#[test]
fn rejects_source_symlinks_without_following_them() {
    let fixture = Fixture::new();
    std::os::unix::fs::symlink(
        fixture.tls().join("Cargo.toml"),
        fixture.quic().join("linked"),
    )
    .unwrap();
    assert!(stage(&fixture.quic(), &fixture.output()).is_err());
    assert!(audit_pair(&fixture.quic()).is_err());
    assert!(!fixture.output().exists());
}
