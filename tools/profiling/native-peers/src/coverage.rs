use std::{io, path::Path};

/// Freeze the owned child before copying LLVM's continuously mapped counters.
/// Resume on every exit path, including a failed copy or stop confirmation.
#[cfg(target_os = "macos")]
pub(super) fn snapshot(pid: u32, source: &Path, destination: &Path) -> io::Result<()> {
    use std::{
        fs,
        process::Command,
        thread,
        time::{Duration, Instant},
    };
    let pid = i32::try_from(pid).map_err(io::Error::other)?;
    if pid <= 0 {
        return Err(io::Error::other("invalid child process ID"));
    }
    struct Resume(i32);
    impl Drop for Resume {
        fn drop(&mut self) {
            // SAFETY: this is the live owned server child, never a process group.
            let _ = unsafe { libc::kill(self.0, libc::SIGCONT) };
        }
    }
    // SAFETY: pid identifies the owned server child. SIGSTOP only pauses it.
    if unsafe { libc::kill(pid, libc::SIGSTOP) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let _resume = Resume(pid);
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let state = Command::new("ps")
            .args(["-o", "state=", "-p"])
            .arg(pid.to_string())
            .output()?;
        if !state.status.success() {
            return Err(io::Error::other("could not inspect paused server"));
        }
        if String::from_utf8_lossy(&state.stdout)
            .trim()
            .starts_with('T')
        {
            break;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("server did not stop for profile snapshot"));
        }
        thread::sleep(Duration::from_millis(1));
    }
    if fs::metadata(source)?.len() == 0 {
        return Err(io::Error::other("LLVM continuous profile is empty"));
    }
    fs::copy(source, destination)?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(super) fn snapshot(_pid: u32, _source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::other(
        "continuous profile snapshots require macOS",
    ))
}
