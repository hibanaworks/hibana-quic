//! Private, std-only verifier for the disclosed upstream runner patch.
//!
//! Build: rustc --edition=2021 tools/ci/runner_patch.rs -o runner-patch
//! Usage: runner-patch manifest PATCH
//!        runner-patch apply RUNNER PATCH
//!        runner-patch verify RUNNER PATCH
//!
//! Pins are compiled in. A caller cannot replace them with an input manifest.
//! All subprocess output is captured; errors never include paths or tool output.
#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output, Stdio};

struct Pins<'a> {
    base: &'a str,
    patch: &'a str,
    interop: &'a str,
    trace: &'a str,
}

const PINNED: Pins<'static> = Pins {
    base: "740c05a10b61d65e8abd3ad38d60898004d335d9",
    patch: "0d4e8441495a2b243a3e8dec697bcbd84831ea5e1c18725dfdb62006ab4b68dd",
    interop: "62ebef9d52a2f7e313ad1e5b193facdc2b77c5fe2671e4552ab3964ddbf7d9a9",
    trace: "116d0608bb94e6cead90d0d930070a103bce488fbea9df555db4fe07da0f1de6",
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    Usage,
    PatchRead,
    PatchDigest,
    Hash,
    RunnerRoot,
    Git,
    Base,
    IndexFlags,
    Dirty,
    Changes,
    Content,
    Mode,
    ApplyCheck,
    Apply,
    Output,
}

impl Error {
    fn message(&self) -> &'static str {
        match self {
            Self::Usage => "expected manifest PATCH, apply RUNNER PATCH, or verify RUNNER PATCH",
            Self::PatchRead => "runner patch is unavailable",
            Self::PatchDigest => "runner patch digest mismatch",
            Self::Hash => "runner digest command failed",
            Self::RunnerRoot => "runner path must be a repository root",
            Self::Git => "runner git command failed",
            Self::Base => "runner base changed",
            Self::IndexFlags => "runner index flags are unsupported",
            Self::Dirty => "runner must start clean",
            Self::Changes => "unexpected runner changes",
            Self::Content => "runner patch content changed",
            Self::Mode => "runner file mode changed",
            Self::ApplyCheck => "runner patch check failed",
            Self::Apply => "runner patch application failed",
            Self::Output => "runner manifest output failed",
        }
    }
}

// Only known-small subprocess outputs reach this helper: a digest or git apply.
fn with_input(mut command: Command, input: &[u8]) -> io::Result<Output> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(input),
        None => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "runner subprocess input unavailable",
        )),
    };
    if let Err(error) = result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    child.wait_with_output()
}

fn digest(bytes: &[u8]) -> Result<String, Error> {
    let output = with_input(Command::new("sha256sum"), bytes).map_err(|_| Error::Hash)?;
    if !output.status.success()
        || output.stdout.len() != 68
        || &output.stdout[64..] != b"  -\n"
        || !output.stdout[..64]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(Error::Hash);
    }
    String::from_utf8(output.stdout[..64].to_vec()).map_err(|_| Error::Hash)
}

fn git_command(root: &Path) -> Command {
    let mut command = Command::new("git");
    // Prevent inherited Git settings from redirecting an explicit runner path.
    for (key, _) in env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "--no-pager",
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.fileMode=true",
            "-c",
            "core.ignoreStat=false",
        ])
        .arg("-C")
        .arg(root)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, Error> {
    let output = git_command(root)
        .args(args)
        .output()
        .map_err(|_| Error::Git)?;
    if !output.status.success() {
        return Err(Error::Git);
    }
    Ok(output.stdout)
}

struct RunnerPatch<'a> {
    pins: &'a Pins<'a>,
    bytes: Vec<u8>,
}

impl RunnerPatch<'static> {
    fn load(path: &Path) -> Result<Self, Error> {
        let metadata = fs::metadata(path).map_err(|_| Error::PatchRead)?;
        if !metadata.is_file() || metadata.len() > 1024 * 1024 {
            return Err(Error::PatchRead);
        }
        let bytes = fs::read(path).map_err(|_| Error::PatchRead)?;
        let patch = Self {
            pins: &PINNED,
            bytes,
        };
        patch.check_digest()?;
        Ok(patch)
    }
}

impl RunnerPatch<'_> {
    fn check_digest(&self) -> Result<(), Error> {
        if digest(&self.bytes)? != self.pins.patch {
            return Err(Error::PatchDigest);
        }
        Ok(())
    }

    fn manifest(&self) -> String {
        format!(
            "{{\"base_revision\": \"{}\", \"files\": {{\"interop.py\": \"{}\", \"trace.py\": \"{}\"}}, \"patch_sha256\": \"{}\"}}\n",
            self.pins.base, self.pins.interop, self.pins.trace, self.pins.patch
        )
    }

    fn check_base(&self, root: &Path) -> Result<(), Error> {
        if git(root, &["rev-parse", "--show-prefix"])? != b"\n"
            || git(root, &["rev-parse", "--is-inside-work-tree"])? != b"true\n"
        {
            return Err(Error::RunnerRoot);
        }
        if git(root, &["rev-parse", "--verify", "HEAD"])?
            != format!("{}\n", self.pins.base).as_bytes()
        {
            return Err(Error::Base);
        }
        let tracked = git(root, &["ls-files", "-v", "-z"])?;
        if tracked
            .split(|byte| *byte == 0)
            .filter(|row| !row.is_empty())
            .any(|row| !row.starts_with(b"H "))
        {
            return Err(Error::IndexFlags);
        }
        Ok(())
    }

    fn status(&self, root: &Path) -> Result<Vec<Vec<u8>>, Error> {
        let bytes = git(
            root,
            &[
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
        )?;
        let mut rows: Vec<_> = bytes
            .split(|byte| *byte == 0)
            .filter(|row| !row.is_empty())
            .map(|row| row.to_vec())
            .collect();
        rows.sort();
        Ok(rows)
    }

    fn verify(&self, root: &Path) -> Result<(), Error> {
        self.check_digest()?;
        self.check_base(root)?;
        if self.status(root)? != [b" M interop.py".to_vec(), b" M trace.py".to_vec()] {
            return Err(Error::Changes);
        }
        if !git(
            root,
            &[
                "diff",
                "--summary",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
            ],
        )?
        .is_empty()
        {
            return Err(Error::Mode);
        }
        for (name, expected) in [
            ("interop.py", self.pins.interop),
            ("trace.py", self.pins.trace),
        ] {
            let path = root.join(name);
            if !fs::symlink_metadata(&path)
                .map_err(|_| Error::Content)?
                .file_type()
                .is_file()
            {
                return Err(Error::Content);
            }
            let bytes = fs::read(path).map_err(|_| Error::Content)?;
            if digest(&bytes)? != expected {
                return Err(Error::Content);
            }
        }
        Ok(())
    }

    fn apply(&self, root: &Path) -> Result<(), Error> {
        self.check_digest()?;
        self.check_base(root)?;
        if !self.status(root)?.is_empty() {
            return Err(Error::Dirty);
        }
        for (args, error) in [
            (
                &["apply", "--check", "--whitespace=nowarn", "-"][..],
                Error::ApplyCheck,
            ),
            (&["apply", "--whitespace=nowarn", "-"][..], Error::Apply),
        ] {
            let mut command = git_command(root);
            command.args(args);
            let output = with_input(command, &self.bytes).map_err(|_| error)?;
            if !output.status.success() {
                return Err(error);
            }
        }
        self.verify(root)
    }
}

fn run(args: Vec<OsString>) -> Result<String, Error> {
    let (operation, root, path) = match args.as_slice() {
        [operation, patch] if operation == "manifest" => ("manifest", None, patch),
        [operation, root, patch] if operation == "apply" => ("apply", Some(root), patch),
        [operation, root, patch] if operation == "verify" => ("verify", Some(root), patch),
        _ => return Err(Error::Usage),
    };
    let patch = RunnerPatch::load(Path::new(path))?;
    if let Some(root) = root {
        let root: PathBuf = fs::canonicalize(root).map_err(|_| Error::RunnerRoot)?;
        match operation {
            "apply" => patch.apply(&root)?,
            "verify" => patch.verify(&root)?,
            _ => return Err(Error::Usage),
        }
    }
    Ok(patch.manifest())
}

fn main() -> ExitCode {
    let result = run(env::args_os().skip(1).collect()).and_then(|manifest| {
        io::stdout()
            .lock()
            .write_all(manifest.as_bytes())
            .map_err(|_| Error::Output)
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "{}", error.message());
            ExitCode::from(if error == Error::Usage { 2 } else { 1 })
        }
    }
}

#[cfg(test)]
#[path = "runner_patch_tests.rs"]
mod tests;
