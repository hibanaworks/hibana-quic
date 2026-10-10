//! Native descriptor-relative operations preserve the process file policy.
#[path = "../../examples/hq/support/native_files.rs"]
pub mod fs;
use std::{
    fs::{self as stdfs, OpenOptions},
    os::unix::{fs::MetadataExt, fs::symlink},
};

#[test]
fn descriptor_relative_creation_matches_std_and_refuses_symlinks() {
    let root = std::env::temp_dir().join(format!("hibana-pal-fs-{}", std::process::id()));
    stdfs::create_dir(&root).unwrap();
    let parent = fs::directory(&root).unwrap();
    let expected = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("std-file"))
        .unwrap();
    let actual = fs::create_at(&parent, "native-file").unwrap();
    assert_eq!(
        actual.metadata().unwrap().mode() & 0o777,
        expected.metadata().unwrap().mode() & 0o777
    );
    assert!(fs::create_at(&parent, "native-file").is_err());
    stdfs::create_dir(root.join("std-dir")).unwrap();
    fs::mkdir_at(&parent, "native-dir").unwrap();
    assert_eq!(
        stdfs::metadata(root.join("native-dir")).unwrap().mode() & 0o777,
        stdfs::metadata(root.join("std-dir")).unwrap().mode() & 0o777
    );
    symlink("native-file", root.join("link")).unwrap();
    assert!(fs::read_at(&parent, "link").is_err());
    assert!(fs::create_at(&parent, "link").is_err());
    assert!(fs::create_at(&parent, "../escape").is_err());
    drop((actual, expected, parent));
    stdfs::remove_dir_all(root).unwrap();
}
