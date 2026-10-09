//! Credential file access; decoding belongs to hibana-tls.
pub use hibana_tls::certificate::pem::PrivateKeyDer;
use hibana_tls::secret::Secret;
use std::{fs, path::Path};
type Result<T> = std::result::Result<T, String>;
pub fn certificates(path: &Path) -> Result<Vec<Vec<u8>>> {
    let bytes = fs::read(path)
        .map_err(|e| format!("cannot read certificate file {}: {e}", path.display()))?;
    hibana_tls::certificate::pem::decode_certificates(&bytes)
}
pub fn private_key(path: &Path) -> Result<PrivateKeyDer> {
    let bytes = Secret::new(
        fs::read(path).map_err(|e| format!("cannot read key file {}: {e}", path.display()))?,
    );
    hibana_tls::certificate::pem::decode_private_key(&bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_io_errors_remain_errors_with_path_context() {
        let absent = std::env::temp_dir().join(format!("hibana-absent-pem-{}", std::process::id()));
        assert!(!absent.exists());
        assert!(
            certificates(&absent)
                .unwrap_err()
                .starts_with("cannot read certificate file ")
        );
        assert!(
            private_key(&absent)
                .unwrap_err()
                .starts_with("cannot read key file ")
        );
        // Reading a directory fails on the supported Linux host, too.
        assert!(certificates(&std::env::temp_dir()).is_err());
        assert!(private_key(&std::env::temp_dir()).is_err());
    }
}
