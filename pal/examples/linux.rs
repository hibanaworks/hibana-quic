#[cfg(target_os = "linux")]
include!("native/environment.rs");
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Run this example on linux.");
}
