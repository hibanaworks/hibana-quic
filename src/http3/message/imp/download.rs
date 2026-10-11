//! The explicit 200-response, in-place file download policy.
use crate::http3::message::{Consumer, Error, FieldSection, Result};
use crate::io::RandomAccess;
pub(in crate::http3) struct Download<'a, F>(pub &'a F);
impl<F: RandomAccess> Consumer for Download<'_, F> {
    async fn headers(&mut self, fields: FieldSection<'_>) -> Result<()> {
        if fields.metadata.status != Some(200) {
            return Err("download response was not 200".into());
        }
        Ok(())
    }
    async fn data(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        self.0.write_all_at(bytes, offset).map_err(Error::from)
    }
    async fn complete(&mut self, length: u64) -> Result<()> {
        self.0.set_len(length).map_err(Error::from)
    }
}
