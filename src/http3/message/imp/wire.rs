//! Frame-kind validation; projected localsides own message progression.
use super::super::Result;
pub(in crate::http3) fn unknown(kind: u64) -> Result<()> {
    if matches!(kind, 0 | 1 | 3 | 4 | 5 | 7 | 13) {
        Err("unexpected HTTP/3 frame on response stream".into())
    } else {
        Ok(())
    }
}
