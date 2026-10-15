use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

const CORE: &str = "https://github.com/hibanaworks/hibana";
const REV: &str = "1111111111111111111111111111111111111111";
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    folder: PathBuf,
    quic: PathBuf,
    tls: PathBuf,
    revision: String,
}

impl Fixture {
    fn new() -> Self {
        let folder = std::env::temp_dir().join(format!(
            "hibana-source-pair-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&folder).unwrap();
        let quic = folder.join("hibana-quic");
        let tls = folder.join("hibana-tls");
        fs::create_dir_all(quic.join("tools/ci")).unwrap();
        fs::create_dir_all(tls.join("src")).unwrap();
        fs::write(tls.join("Cargo.toml"), "[package]\nname = \"hibana-tls\"\n").unwrap();
        fs::write(tls.join("src/lib.rs"), b"// committed TLS fixture\n").unwrap();
        let mut fixture = Self {
            folder,
            quic,
            tls,
            revision: String::new(),
        };
        fixture.git(&["init", "-q"]);
        fixture.git(&["add", "."]);
        fixture.git(&[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qm",
            "Synthetic TLS source",
        ]);
        fixture.revision = String::from_utf8(fixture.git(&["rev-parse", "HEAD"]).stdout)
            .unwrap()
            .trim()
            .into();
        fixture.manifest(&fixture.revision);
        fs::write(fixture.quic.join("Cargo.lock"), format!(
            "version = 4\n[[package]]\nname = \"hibana\"\nversion = \"0.0.1\"\nsource = \"git+{CORE}?rev={REV}#{REV}\"\n"
        )).unwrap();
        fs::write(
            fixture.quic.join("tools/ci/pins.env"),
            format!("HIBANA_VERSION=0.0.1\nHIBANA_REVISION={REV}\n"),
        )
        .unwrap();
        let driver = fixture.quic.join("tests/interop/driver");
        fs::create_dir_all(&driver).unwrap();
        for name in ["Cargo.toml", "Cargo.lock"] {
            fs::copy(fixture.quic.join(name), driver.join(name)).unwrap();
        }
        fixture
    }

    fn git(&self, args: &[&str]) -> Output {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.tls)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn manifest(&self, revision: &str) {
        fs::write(self.quic.join("Cargo.toml"), format!(
            "[package.metadata.hibana-source]\nversion = \"0.0.1\"\nrepository = \"{CORE}\"\nrevision = \"{REV}\"\n\n[patch.crates-io]\nhibana = {{ git = \"{CORE}\", rev = \"{REV}\" }}\n\n[dependencies]\nhibana-tls = {{ git = \"https://github.com/hibanaworks/hibana-tls\", rev = \"{revision}\" }}\n"
        )).unwrap();
    }

    fn stage(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_stage-paired-source"))
            .current_dir(&self.quic)
            .arg("--output")
            .arg(self.folder.join("output"))
            .output()
            .unwrap()
    }

    fn rejected_without_export(&self) {
        assert!(!self.stage().status.success());
        assert!(!self.folder.join("output").exists());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.folder).unwrap();
    }
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn exports_the_actual_committed_bytes_and_both_consumer_locks() {
    let fixture = Fixture::new();
    let result = fixture.stage();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = fixture.folder.join("output");
    let pair = json(&output.join("source-pair.json"));
    assert_eq!(pair["tls_revision"], fixture.revision);
    assert_eq!(pair["hibana_revision"], REV);
    assert!(fs::metadata(output.join("source-pair.json")).unwrap().len() < 16384);
    assert!(!output.join("hibana-tls/.git").exists());
    let hashes = json(&output.join("source-files.json"));
    for name in ["Cargo.toml", "src/lib.rs"] {
        let committed = fixture.git(&["show", &format!("HEAD:{name}")]).stdout;
        assert_eq!(
            fs::read(output.join("hibana-tls").join(name)).unwrap(),
            committed
        );
        assert_eq!(
            hashes[format!("hibana-tls/{name}")],
            format!("{:x}", Sha256::digest(committed))
        );
    }
    for name in ["Cargo.lock", "tests/interop/driver/Cargo.lock"] {
        assert_eq!(
            fs::read(output.join("hibana-quic").join(name)).unwrap(),
            fs::read(fixture.quic.join(name)).unwrap()
        );
    }
}

#[test]
fn rejects_another_tls_commit_without_creating_an_export() {
    let fixture = Fixture::new();
    fixture.manifest("0000000000000000000000000000000000000000");
    fixture.rejected_without_export();
}

#[test]
fn rejects_both_modified_and_untracked_tls() {
    for name in ["Cargo.toml", "extra.rs"] {
        let fixture = Fixture::new();
        fs::write(fixture.tls.join(name), "unexpected source\n").unwrap();
        fixture.rejected_without_export();
    }
}

#[test]
fn cannot_substitute_missing_tls() {
    let fixture = Fixture::new();
    fs::remove_dir_all(&fixture.tls).unwrap();
    fixture.rejected_without_export();
}

#[test]
fn rejects_root_and_driver_core_mismatches_before_export() {
    let source = format!("git+{CORE}?rev={REV}#{REV}");
    for (name, before, after) in [
        (
            "Cargo.lock",
            REV,
            "2222222222222222222222222222222222222222",
        ),
        (
            "tools/ci/pins.env",
            REV,
            "2222222222222222222222222222222222222222",
        ),
        (
            "tests/interop/driver/Cargo.lock",
            source.as_str(),
            "registry+https://github.com/rust-lang/crates.io-index",
        ),
        (
            "tests/interop/driver/Cargo.toml",
            REV,
            "2222222222222222222222222222222222222222",
        ),
    ] {
        let fixture = Fixture::new();
        let path = fixture.quic.join(name);
        fs::write(
            &path,
            fs::read_to_string(&path).unwrap().replace(before, after),
        )
        .unwrap();
        fixture.rejected_without_export();
    }
}

#[test]
fn exports_core_free_host_tools_without_relaxing_consumer_checks() {
    let fixture = Fixture::new();
    let tool = fixture.quic.join("tools/ci/host-tool");
    fs::create_dir_all(&tool).unwrap();
    fs::write(
        tool.join("Cargo.toml"),
        "[package]\nname = \"host-tool\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(
        tool.join("Cargo.lock"),
        "version = 4\n[[package]]\nname = \"host-tool\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let result = fixture.stage();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(
            fixture
                .folder
                .join("output/hibana-quic/tools/ci/host-tool/Cargo.lock")
        )
        .unwrap(),
        fs::read(tool.join("Cargo.lock")).unwrap()
    );
}

#[test]
fn rejects_a_foreign_path_before_writing_any_source() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.folder.join("outside")).unwrap();
    let manifest = fixture.quic.join("Cargo.toml");
    fs::write(
        &manifest,
        fs::read_to_string(&manifest).unwrap() + "outside = { path = \"../outside\" }\n",
    )
    .unwrap();
    fixture.rejected_without_export();
}

#[cfg(unix)]
#[test]
fn rejects_a_source_symlink_before_export() {
    let fixture = Fixture::new();
    std::os::unix::fs::symlink(
        fixture.tls.join("src/lib.rs"),
        fixture.quic.join("linked.rs"),
    )
    .unwrap();
    fixture.rejected_without_export();
}
