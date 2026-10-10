//! Descriptor-relative HTTP file access and atomic download publication.
#![allow(dead_code)]
use super::native_files as native;
use super::random;
use std::{
    fs::{self, File},
    io,
    path::Path,
};
type Result<T> = std::result::Result<T, String>;
const MAX_TARGET: usize = 1000;
pub(crate) fn url_target<'a>(value: &'a str, name: &str, port: u16) -> Result<&'a str> {
    if value.starts_with('/') {
        return Ok(value);
    }
    let rest = value
        .strip_prefix("https://")
        .ok_or("requests must be /paths or https:// URLs")?;
    let (authority, path) = rest.split_once('/').ok_or("URL must contain a file path")?;
    if authority.contains('@') {
        return Err("URL user information is forbidden".into());
    }
    let expected = format!("{name}:{port}");
    if !(authority.eq_ignore_ascii_case(&expected)
        || port == 443 && authority.eq_ignore_ascii_case(name))
    {
        return Err("URL authority must match --server-name and --connect port".into());
    }
    let start = value.len() - path.len() - 1;
    Ok(&value[start..])
}
pub(crate) fn path_components(target: &str) -> Result<Vec<String>> {
    if target.len() > MAX_TARGET
        || !target.starts_with('/')
        || target.starts_with("//")
        || target
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7f || matches!(b, b'\\' | b'?' | b'#'))
    {
        return Err("invalid or overlong HTTP/0.9 file target".into());
    }
    let mut decoded = Vec::with_capacity(target.len());
    let raw = target.as_bytes();
    let mut i = 1;
    while i < raw.len() {
        if raw[i] == b'%' {
            let hex = |b: u8| -> Option<u8> {
                match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                }
            };
            if i + 2 >= raw.len() {
                return Err("truncated percent escape".into());
            }
            let v = hex(raw[i + 1])
                .and_then(|a| hex(raw[i + 2]).map(|b| (a << 4) | b))
                .ok_or("invalid percent escape")?;
            if v < 0x20 || v == 0x7f || matches!(v, b'/' | b'\\') {
                return Err("encoded separator/control is forbidden".into());
            }
            decoded.push(v);
            i += 3;
        } else {
            decoded.push(raw[i]);
            i += 1;
        }
    }
    let value = String::from_utf8(decoded).map_err(|_| "file target is not UTF-8")?;
    let mut components = Vec::new();
    for component in value.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.starts_with(".hibana-")
        {
            return Err("empty, dot or reserved path component".into());
        }
        components.push(component.to_owned());
    }
    Ok(components)
}
pub(crate) fn parse_get(bytes: &[u8]) -> Result<Vec<String>> {
    let line = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .ok_or("GET request requires line ending and stream FIN")?;
    let target = line
        .strip_prefix(b"GET ")
        .ok_or("only HTTP/0.9 GET is supported")?;
    path_components(std::str::from_utf8(target).map_err(|_| "GET target is not UTF-8")?)
}
pub(crate) struct SafeRoot {
    directory: File,
}
impl SafeRoot {
    pub(crate) fn open(path: &Path, create: bool) -> Result<Self> {
        if create {
            fs::create_dir_all(path).map_err(|e| format!("create download root: {e}"))?;
        }
        let canonical = fs::canonicalize(path)
            .map_err(|e| format!("canonical root {}: {e}", path.display()))?;
        let directory = native::directory(&canonical).map_err(|e| format!("open root: {e}"))?;
        Ok(Self { directory })
    }
    fn parent(&self, components: &[String], create: bool) -> Result<(File, String)> {
        if components.iter().any(|c| {
            c.is_empty()
                || c == "."
                || c == ".."
                || c.contains(['/', '\\', '\0'])
                || c.starts_with(".hibana-")
        }) {
            return Err("invalid relative path component".into());
        }
        let (last, parents) = components.split_last().ok_or("missing file name")?;
        let mut dir = self
            .directory
            .try_clone()
            .map_err(|e| format!("clone root descriptor: {e}"))?;
        for component in parents {
            let open = || native::directory_at(&dir, component);
            let next = match open() {
                Ok(file) => file,
                Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
                    match native::mkdir_at(&dir, component) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(format!("create relative directory: {e}")),
                    }
                    open().map_err(|e| format!("open relative directory without symlinks: {e}"))?
                }
                Err(e) => return Err(format!("open relative directory without symlinks: {e}")),
            };
            dir = next;
        }
        Ok((dir, last.clone()))
    }
    pub(crate) fn read(&self, components: &[String]) -> Result<File> {
        let (parent, name) = self.parent(components, false)?;
        let file =
            native::read_at(&parent, &name).map_err(|e| format!("open requested file: {e}"))?;
        if !file
            .metadata()
            .map_err(|e| format!("file metadata: {e}"))?
            .is_file()
        {
            return Err("requested object is not a regular file".into());
        }
        Ok(file)
    }
    pub(crate) fn create(&self, components: &[String]) -> Result<Download> {
        let (parent, name) = self.parent(components, true)?;
        if native::exists_at(&parent, &name).map_err(|e| format!("destination check: {e}"))? {
            return Err("download destination already exists; refusing overwrite".into());
        }
        let temp = format!(".hibana-{:016x}.part", u64::from_be_bytes(random::<8>()?));
        let file = native::create_at(&parent, &temp)
            .map_err(|e| format!("create bounded download staging file: {e}"))?;
        Ok(Download {
            file,
            parent,
            name,
            temp: Some(temp),
        })
    }
}
pub(crate) struct Download {
    pub(crate) file: File,
    parent: File,
    name: String,
    temp: Option<String>,
}
impl Download {
    pub(crate) fn finish(&mut self) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|e| format!("sync completed body: {e}"))?;
        let temp = self.temp.as_ref().ok_or("download already finalized")?;
        native::link_at(&self.parent, temp, &self.name)
            .map_err(|e| format!("publish completed file without overwrite: {e}"))?;
        native::remove_at(&self.parent, temp).map_err(|e| format!("remove staging link: {e}"))?;
        self.temp = None;
        self.parent
            .sync_all()
            .map_err(|e| format!("sync download directory: {e}"))?;
        Ok(())
    }
}
impl Drop for Download {
    fn drop(&mut self) {
        if let Some(temp) = self.temp.take() {
            let _ = native::remove_at(&self.parent, &temp);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::{
        io::{Read, Write},
        os::unix::fs::symlink,
    };
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "hibana-hq-test-{:016x}",
                u64::from_be_bytes(random().unwrap())
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn components(target: &str) -> Vec<String> {
        path_components(target).unwrap()
    }
    #[test]
    fn path_decoder_rejects_traversal_separators_and_injection() {
        for target in [
            "../x",
            "//pal/x",
            "/../x",
            "/a/./x",
            "/a//x",
            "/a/",
            "/%2e%2e/x",
            "/a%2fb",
            "/a%5cb",
            "/a\\b",
            "/%00",
            "/%0a",
            "/%",
            "/%xy",
            "/x?query",
            "/x#fragment",
            "/a b",
            "/x\r\nGET /secret",
            "/.hibana-temporary",
        ] {
            assert!(path_components(target).is_err(), "accepted {target:?}");
        }
        assert_eq!(
            components("/directory/hello%20world.txt"),
            ["directory", "hello world.txt"]
        );
        assert_eq!(components("/%252e%252e"), ["%2e%2e"]);
    }
    #[test]
    fn get_parser_requires_method_line_end_and_no_extra_headers() {
        assert_eq!(parse_get(b"GET /hello\r\n").unwrap(), ["hello"]);
        assert_eq!(parse_get(b"GET /hello\n").unwrap(), ["hello"]);
        for bad in [
            &b"POST /hello\r\n"[..],
            &b"GET /hello"[..],
            &b"GET /hello HTTP/1.1\r\n"[..],
            &b"GET /hello\r\nX: header\r\n"[..],
        ] {
            assert!(parse_get(bad).is_err());
        }
    }
    #[test]
    fn url_authority_is_bound_to_verified_name_and_port() {
        assert_eq!(
            url_target("https://localhost:4433/a", "localhost", 4433).unwrap(),
            "/a"
        );
        assert_eq!(
            url_target("https://LOCALHOST/a", "localhost", 443).unwrap(),
            "/a"
        );
        for url in [
            "http://localhost:4433/a",
            "https://elsewhere:4433/a",
            "https://user@localhost:4433/a",
            "https://localhost:4434/a",
            "https://localhost:4433",
        ] {
            assert!(url_target(url, "localhost", 4433).is_err());
        }
    }
    #[test]
    fn symlink_parent_cannot_escape_server_or_download_root() {
        let f = Fixture::new();
        let root = f.0.join("root");
        let outside = f.0.join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), b"private").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        let safe = SafeRoot::open(&root, false).unwrap();
        assert!(safe.read(&components("/escape/secret")).is_err());
        assert!(safe.create(&components("/escape/new")).is_err());
        assert!(!outside.join("new").exists());
    }
    #[test]
    fn final_symlink_is_never_followed_or_overwritten() {
        let f = Fixture::new();
        fs::write(f.0.join("target"), b"original").unwrap();
        symlink(f.0.join("target"), f.0.join("alias")).unwrap();
        let safe = SafeRoot::open(&f.0, false).unwrap();
        assert!(safe.read(&components("/alias")).is_err());
        assert!(safe.create(&components("/alias")).is_err());
        assert_eq!(fs::read(f.0.join("target")).unwrap(), b"original");
    }
    #[test]
    fn held_root_descriptor_survives_path_replacement_without_escape() {
        let f = Fixture::new();
        let root = f.0.join("root");
        let moved = f.0.join("moved");
        let outside = f.0.join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(root.join("file"), b"authorized").unwrap();
        fs::write(outside.join("file"), b"outside").unwrap();
        let safe = SafeRoot::open(&root, false).unwrap();
        fs::rename(&root, &moved).unwrap();
        symlink(&outside, &root).unwrap();
        let mut content = String::new();
        safe.read(&components("/file"))
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "authorized");
    }
    #[test]
    fn complete_download_publishes_only_at_fin_without_overwrite() {
        let f = Fixture::new();
        let safe = SafeRoot::open(&f.0, false).unwrap();
        let mut download = safe.create(&components("/nested/body")).unwrap();
        download.file.write_all(b"complete").unwrap();
        assert!(!f.0.join("nested/body").exists());
        download.finish().unwrap();
        assert_eq!(fs::read(f.0.join("nested/body")).unwrap(), b"complete");
        assert!(safe.create(&components("/nested/body")).is_err());
    }
    #[test]
    fn failed_download_removes_staging_and_racing_destination_is_preserved() {
        let f = Fixture::new();
        let safe = SafeRoot::open(&f.0, false).unwrap();
        {
            let mut download = safe.create(&components("/body")).unwrap();
            download.file.write_all(b"partial").unwrap();
        }
        assert_eq!(fs::read_dir(&f.0).unwrap().count(), 0);
        let mut download = safe.create(&components("/body")).unwrap();
        download.file.write_all(b"ours").unwrap();
        fs::write(f.0.join("body"), b"existing").unwrap();
        assert!(download.finish().is_err());
        drop(download);
        assert_eq!(fs::read(f.0.join("body")).unwrap(), b"existing");
        assert_eq!(fs::read_dir(&f.0).unwrap().count(), 1);
    }
    #[test]
    fn named_pipe_cannot_block_the_server_before_regular_file_check() {
        let f = Fixture::new();
        let status = std::process::Command::new("mkfifo")
            .arg(f.0.join("pipe"))
            .status()
            .unwrap();
        assert!(status.success());
        let root = SafeRoot::open(&f.0, false).unwrap();
        assert!(root.read(&components("/pipe")).is_err());
    }
}
