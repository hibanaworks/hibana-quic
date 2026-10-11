//! Synthetic repositories exercise the same private implementation. Alternate
//! pins are constructed only here, never accepted by the production CLI.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    directory: PathBuf,
    root: PathBuf,
    base: String,
    bytes: Vec<u8>,
    patch_hash: String,
    interop_hash: String,
    trace_hash: String,
}

impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = env::temp_dir().join(format!(
            "runner-patch-test-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let root = directory.join("runner with spaces");
        fs::create_dir_all(&root).unwrap();
        let mut fixture = Self {
            directory,
            root,
            base: String::new(),
            bytes: Vec::new(),
            patch_hash: String::new(),
            interop_hash: String::new(),
            trace_hash: String::new(),
        };
        fixture.git(&["init", "--quiet"]);
        fixture.git(&["config", "user.name", "Hayato Ohhashi"]);
        fixture.git(&["config", "user.email", "o8@vmm.dev"]);
        fixture.git(&["config", "commit.gpgsign", "false"]);
        fs::write(fixture.root.join("interop.py"), "old interop\n").unwrap();
        fs::write(fixture.root.join("trace.py"), "old trace\n").unwrap();
        fs::write(fixture.root.join("unchanged.txt"), "unchanged\n").unwrap();
        fixture.git(&["add", "--all"]);
        fixture.git(&[
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            "Synthetic runner base",
        ]);
        fixture.base = String::from_utf8(fixture.git(&["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned();
        fixture.write_expected();
        fixture.interop_hash = digest(b"new interop\n").unwrap();
        fixture.trace_hash = digest(b"new trace\n").unwrap();
        fixture.bytes = fixture.git(&["diff", "--binary", "--no-ext-diff", "--no-textconv"]);
        fixture.patch_hash = digest(&fixture.bytes).unwrap();
        fixture.git(&["checkout", "--", "interop.py", "trace.py"]);
        fixture
    }

    fn git(&self, args: &[&str]) -> Vec<u8> {
        let output = git_command(&self.root)
            .env("GIT_AUTHOR_NAME", "Hayato Ohhashi")
            .env("GIT_AUTHOR_EMAIL", "o8@vmm.dev")
            .env("GIT_COMMITTER_NAME", "Hayato Ohhashi")
            .env("GIT_COMMITTER_EMAIL", "o8@vmm.dev")
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "fixture git command failed");
        output.stdout
    }

    fn write_expected(&self) {
        fs::write(self.root.join("interop.py"), "new interop\n").unwrap();
        fs::write(self.root.join("trace.py"), "new trace\n").unwrap();
    }

    fn with_patch<T>(&self, test: impl FnOnce(RunnerPatch<'_>) -> T) -> T {
        let pins = Pins {
            base: &self.base,
            patch: &self.patch_hash,
            interop: &self.interop_hash,
            trace: &self.trace_hash,
        };
        test(RunnerPatch {
            pins: &pins,
            bytes: self.bytes.clone(),
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn digest_matches_known_sha256() {
    assert_eq!(
        digest(b"abc").unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn manifest_has_exact_pinned_dictionary_and_newline() {
    let patch = RunnerPatch {
        pins: &PINNED,
        bytes: Vec::new(),
    };
    assert_eq!(patch.manifest(), concat!(
        "{\"base_revision\": \"740c05a10b61d65e8abd3ad38d60898004d335d9\", ",
        "\"files\": {\"interop.py\": \"62ebef9d52a2f7e313ad1e5b193facdc2b77c5fe2671e4552ab3964ddbf7d9a9\", ",
        "\"trace.py\": \"116d0608bb94e6cead90d0d930070a103bce488fbea9df555db4fe07da0f1de6\"}, ",
        "\"patch_sha256\": \"0d4e8441495a2b243a3e8dec697bcbd84831ea5e1c18725dfdb62006ab4b68dd\"}\n"
    ));
}

#[test]
fn cli_rejects_missing_extra_unknown_and_manifest_override_arguments() {
    for args in [
        vec![],
        vec!["manifest"],
        vec!["apply", "root"],
        vec!["verify", "root"],
        vec!["unknown", "root", "patch"],
        vec!["manifest", "patch", "manifest.json"],
        vec!["apply", "root", "patch", "manifest.json"],
    ] {
        assert_eq!(
            run(args.into_iter().map(OsString::from).collect()),
            Err(Error::Usage)
        );
    }
}

#[test]
fn cli_rejects_synthetic_patch_even_with_valid_git_fixture() {
    let fixture = Fixture::new();
    let path = fixture.directory.join("runner.patch");
    fs::write(&path, &fixture.bytes).unwrap();
    for command in ["manifest", "apply", "verify"] {
        let mut args = vec![OsString::from(command)];
        if command != "manifest" {
            args.push(fixture.root.as_os_str().to_owned());
        }
        args.push(path.as_os_str().to_owned());
        assert_eq!(run(args), Err(Error::PatchDigest));
    }
    assert!(fixture.git(&["status", "--porcelain"]).is_empty());
}

#[test]
fn apply_and_verify_accept_exact_fixture_and_reapply_is_rejected() {
    let fixture = Fixture::new();
    fixture.with_patch(|patch| {
        assert_eq!(patch.apply(&fixture.root), Ok(()));
        assert_eq!(patch.verify(&fixture.root), Ok(()));
        assert_eq!(patch.apply(&fixture.root), Err(Error::Dirty));
    });
}

#[test]
fn verify_rejects_clean_unpatched_runner() {
    let fixture = Fixture::new();
    fixture.with_patch(|patch| assert_eq!(patch.verify(&fixture.root), Err(Error::Changes)));
}

#[test]
fn apply_and_verify_reject_patch_digest_mutation_before_changes() {
    let fixture = Fixture::new();
    fixture.with_patch(|mut patch| {
        patch.bytes.push(b'\n');
        assert_eq!(patch.apply(&fixture.root), Err(Error::PatchDigest));
        fixture.write_expected();
        assert_eq!(patch.verify(&fixture.root), Err(Error::PatchDigest));
    });
}

#[test]
fn apply_rejects_dirty_tracked_and_untracked_files_without_patching() {
    let fixture = Fixture::new();
    fixture.with_patch(|patch| {
        fs::write(fixture.root.join("unchanged.txt"), "dirty\n").unwrap();
        assert_eq!(patch.apply(&fixture.root), Err(Error::Dirty));
        fixture.git(&["checkout", "--", "unchanged.txt"]);
        fs::write(fixture.root.join("untracked\nname"), "untracked\n").unwrap();
        assert_eq!(patch.apply(&fixture.root), Err(Error::Dirty));
        assert_eq!(
            fs::read(fixture.root.join("interop.py")).unwrap(),
            b"old interop\n"
        );
    });
}

#[test]
fn apply_and_verify_reject_different_head() {
    let fixture = Fixture::new();
    fixture.git(&[
        "commit",
        "--quiet",
        "--allow-empty",
        "--no-gpg-sign",
        "-m",
        "Different runner base",
    ]);
    fixture.with_patch(|patch| {
        assert_eq!(patch.apply(&fixture.root), Err(Error::Base));
        fixture.write_expected();
        assert_eq!(patch.verify(&fixture.root), Err(Error::Base));
    });
}

#[test]
fn verify_rejects_file_content_and_missing_file_mutants() {
    let fixture = Fixture::new();
    fixture.with_patch(|patch| {
        patch.apply(&fixture.root).unwrap();
        fs::write(fixture.root.join("interop.py"), "mutant interop\n").unwrap();
        assert_eq!(patch.verify(&fixture.root), Err(Error::Content));
        fixture.write_expected();
        fs::write(fixture.root.join("trace.py"), "mutant trace\n").unwrap();
        assert_eq!(patch.verify(&fixture.root), Err(Error::Content));
        fs::remove_file(fixture.root.join("trace.py")).unwrap();
        assert_eq!(patch.verify(&fixture.root), Err(Error::Changes));
    });
}

#[test]
fn verify_rejects_extra_changed_untracked_and_staged_files() {
    let fixture = Fixture::new();
    fixture.with_patch(|patch| {
        patch.apply(&fixture.root).unwrap();
        fs::write(fixture.root.join("unchanged.txt"), "dirty\n").unwrap();
        assert_eq!(patch.verify(&fixture.root), Err(Error::Changes));
        fixture.git(&["checkout", "--", "unchanged.txt"]);
        fs::write(fixture.root.join("extra.py"), "extra\n").unwrap();
        assert_eq!(patch.verify(&fixture.root), Err(Error::Changes));
        fs::remove_file(fixture.root.join("extra.py")).unwrap();
        fixture.git(&["add", "interop.py", "trace.py"]);
        assert_eq!(patch.verify(&fixture.root), Err(Error::Changes));
    });
}

#[test]
fn apply_and_verify_reject_hidden_index_flags() {
    let fixture = Fixture::new();
    fixture.with_patch(|patch| {
        fixture.git(&["update-index", "--assume-unchanged", "unchanged.txt"]);
        assert_eq!(patch.apply(&fixture.root), Err(Error::IndexFlags));
        fixture.git(&["update-index", "--no-assume-unchanged", "unchanged.txt"]);
        patch.apply(&fixture.root).unwrap();
        fixture.git(&["update-index", "--skip-worktree", "unchanged.txt"]);
        assert_eq!(patch.verify(&fixture.root), Err(Error::IndexFlags));
    });
}

#[test]
fn rejects_nested_source_directory() {
    let fixture = Fixture::new();
    let nested = fixture.root.join("nested");
    fs::create_dir(&nested).unwrap();
    fixture.with_patch(|patch| {
        assert_eq!(patch.apply(&nested), Err(Error::RunnerRoot));
        assert_eq!(patch.verify(&nested), Err(Error::RunnerRoot));
    });
}

#[test]
fn invalid_but_hash_matching_patch_fails_preflight_without_changes() {
    let mut fixture = Fixture::new();
    fixture.bytes = b"not a patch\n".to_vec();
    fixture.patch_hash = digest(&fixture.bytes).unwrap();
    fixture.with_patch(|patch| assert_eq!(patch.apply(&fixture.root), Err(Error::ApplyCheck)));
    assert!(fixture.git(&["status", "--porcelain"]).is_empty());
}

#[cfg(unix)]
#[test]
fn verify_rejects_mode_change_and_symlink_mutants() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let fixture = Fixture::new();
    fixture.with_patch(|patch| {
        patch.apply(&fixture.root).unwrap();
        let path = fixture.root.join("interop.py");
        let original = fs::metadata(&path).unwrap().permissions();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(patch.verify(&fixture.root), Err(Error::Mode));
        fs::set_permissions(&path, original).unwrap();
        fs::remove_file(&path).unwrap();
        symlink(fixture.root.join("trace.py"), &path).unwrap();
        assert_eq!(patch.verify(&fixture.root), Err(Error::Changes));
    });
}

#[test]
fn fixture_commits_keep_required_author_and_committer() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.git(&["show", "-s", "--format=%an <%ae>%n%cn <%ce>"]),
        b"Hayato Ohhashi <o8@vmm.dev>\nHayato Ohhashi <o8@vmm.dev>\n"
    );
}

#[test]
fn apply_checks_final_file_digests_instead_of_trusting_git_success() {
    let mut fixture = Fixture::new();
    fixture.trace_hash = digest(b"different expected trace\n").unwrap();
    fixture.with_patch(|patch| {
        assert_eq!(patch.apply(&fixture.root), Err(Error::Content));
        assert_eq!(
            fs::read(fixture.root.join("trace.py")).unwrap(),
            b"new trace\n"
        );
    });
}
