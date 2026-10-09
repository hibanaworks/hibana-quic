#[cfg(target_os = "macos")]
include!("native/environment.rs");
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("Run this example on macos.");
}
