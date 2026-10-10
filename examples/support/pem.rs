//! Credential file access; decoding belongs to hibana-tls.
pub use hibana_tls::certificate::pem::PrivateKeyDer;
use hibana_tls::secret::Secret;
use std::{fs, io::Read, path::Path};
type Result<T> = std::result::Result<T, String>;
pub fn certificates<'a>(
    path: &Path,
    output: &'a mut [u8],
    certificates: &mut [&'a [u8]],
) -> Result<usize> {
    let bytes = fs::read(path)
        .map_err(|e| format!("cannot read certificate file {}: {e}", path.display()))?;
    hibana_tls::certificate::pem::decode_certificates(&bytes, output, certificates)
        .map_err(str::to_owned)
}
pub fn private_key<'a>(path: &Path, output: &'a mut [u8]) -> Result<PrivateKeyDer<'a>> {
    let mut bytes = Secret::new([0; 16384]);
    let mut file = fs::File::open(path)
        .map_err(|e| format!("cannot read key file {}: {e}", path.display()))?;
    let mut used = 0;
    loop {
        if used == bytes.len() {
            if file.read(&mut [0; 1]).map_err(|e| e.to_string())? != 0 {
                return Err("key PEM exceeds storage".into());
            }
            break;
        }
        let count = file.read(&mut bytes[used..]).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        used += count;
    }
    hibana_tls::certificate::pem::decode_private_key(&bytes[..used], output).map_err(str::to_owned)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_io_errors_remain_errors_with_path_context() {
        let absent = std::env::temp_dir().join(format!("hibana-absent-pem-{}", std::process::id()));
        assert!(!absent.exists());
        assert!(
            certificates(&absent, &mut [0; 32], &mut [&[] as &[u8]; 1])
                .unwrap_err()
                .starts_with("cannot read certificate file ")
        );
        assert!(
            private_key(&absent, &mut [0; 32])
                .unwrap_err()
                .starts_with("cannot read key file ")
        );
        // Reading a directory fails on the supported Linux host, too.
        assert!(certificates(&std::env::temp_dir(), &mut [0; 32], &mut [&[] as &[u8]; 1]).is_err());
        assert!(private_key(&std::env::temp_dir(), &mut [0; 32]).is_err());
    }
}
