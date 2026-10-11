//! Caller-owned memory shared by native HTTP/3 client and server bindings.
/// The bounded byte and field storage retained for one HTTP exchange.
/// It contains no connection progress or platform I/O.
pub struct Storage<const BYTES: usize = 4096, const HEADERS: usize = { crate::http3::FIELD_LIMIT }>
{
    pub(crate) input: [u8; BYTES],
    pub(crate) output: [u8; BYTES],
    pub(crate) request_body: [u8; BYTES],
    pub(crate) response_body: [u8; BYTES],
    pub(crate) request_headers: [u8; HEADERS],
    pub(crate) response_headers: [u8; HEADERS],
}
impl<const B: usize, const H: usize> Storage<B, H> {
    pub const fn new() -> Self {
        Self {
            input: [0; B],
            output: [0; B],
            request_body: [0; B],
            response_body: [0; B],
            request_headers: [0; H],
            response_headers: [0; H],
        }
    }
}
impl<const B: usize, const H: usize> Default for Storage<B, H> {
    fn default() -> Self {
        Self::new()
    }
}
