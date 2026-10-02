//! Bounded CRYPTO stream reassembly and TLS handshake framing.
//!
//! This is not a TLS implementation: it neither authenticates a peer nor installs
//! traffic keys. Callers MUST supply only packet-authenticated CRYPTO bytes, keep
//! one instance per encryption level, and feed contiguous bytes to an audited
//! TLS implementation. 0-RTT cannot carry CRYPTO (RFC 9000 §12.4).

const MAX_OFFSET: u64 = (1 << 62) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidStorage,
    OffsetOverflow,
    BufferExceeded,
    ConflictingOverlap,
    ConsumeBeyondReady,
    Truncated,
    MessageTooLarge,
}

/// Sliding, fixed-capacity receive window. Storage belongs to the caller.
/// One presence bit per byte of data; the caller supplies at least
/// `bitmap_bytes(capacity)` metadata bytes. No heap or pointer leases.
pub struct CryptoBuffer<'a> {
    bytes: &'a mut [u8],
    present: &'a mut [u8],
    base: u64,
    head: usize,
}

/// Metadata bytes required for a fixed receive window, without overflow.
pub const fn bitmap_bytes(capacity:usize)->usize{capacity.div_ceil(8)}

impl<'a> CryptoBuffer<'a> {
    pub fn new(bytes: &'a mut [u8], present: &'a mut [u8]) -> Result<Self, Error> {
        if bytes.is_empty() || present.len() < bitmap_bytes(bytes.len()) {
            return Err(Error::InvalidStorage);
        }
        let present=&mut present[..bitmap_bytes(bytes.len())];
        present.fill(0);
        Ok(Self {
            bytes,
            present,
            base: 0,
            head: 0,
        })
    }

    pub fn consumed(&self) -> u64 {
        self.base
    }
    pub fn capacity(&self) -> usize {
        self.bytes.len()
    }

    fn index(&self, relative: usize) -> usize {
        // Avoid a potentially overflowing head + relative on 32-bit targets.
        let tail = self.bytes.len() - self.head;
        if relative < tail {
            self.head + relative
        } else {
            relative - tail
        }
    }

    fn is_present(&self,slot:usize)->bool{self.present[slot/8]&(1<<(slot%8))!=0}
    fn set_present(&mut self,slot:usize,value:bool){
        let bit=1<<(slot%8);if value{self.present[slot/8]|=bit;}else{self.present[slot/8]&=!bit;}
    }

    /// Insert a complete fragment transactionally. Conflicting retained overlap
    /// and capacity failures leave the existing state unchanged. Already consumed
    /// bytes are ignored, as their retransmission cannot change the TLS transcript.
    pub fn insert(&mut self, offset: u64, data: &[u8]) -> Result<(), Error> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        if offset > MAX_OFFSET || end > MAX_OFFSET {
            return Err(Error::OffsetOverflow);
        }
        if end <= self.base {
            return Ok(());
        }
        if end - self.base > self.bytes.len() as u64 {
            return Err(Error::BufferExceeded);
        }
        let start = offset.max(self.base);
        let skip = (start - offset) as usize;
        let relative = (start - self.base) as usize;
        for (i, byte) in data[skip..].iter().enumerate() {
            let slot = self.index(relative + i);
            if self.is_present(slot) && self.bytes[slot] != *byte {
                return Err(Error::ConflictingOverlap);
            }
        }
        for (i, byte) in data[skip..].iter().enumerate() {
            let slot = self.index(relative + i);
            self.bytes[slot] = *byte;
            self.set_present(slot,true);
        }
        Ok(())
    }

    pub fn ready_len(&self) -> usize {
        (0..self.bytes.len())
            .take_while(|i| self.is_present(self.index(*i)))
            .count()
    }

    /// Contiguous ready bytes, split only at the circular storage boundary.
    pub fn ready(&self) -> (&[u8], &[u8]) {
        let n = self.ready_len();
        let first = n.min(self.bytes.len() - self.head);
        (
            &self.bytes[self.head..self.head + first],
            &self.bytes[..n - first],
        )
    }

    /// Call only for bytes actually accepted by the TLS transcript consumer.
    pub fn consume(&mut self, n: usize) -> Result<(), Error> {
        if n > self.ready_len() {
            return Err(Error::ConsumeBeyondReady);
        }
        let next = self
            .base
            .checked_add(n as u64)
            .ok_or(Error::OffsetOverflow)?;
        if next > MAX_OFFSET {
            return Err(Error::OffsetOverflow);
        }
        for i in 0..n {
            let slot = self.index(i);
            self.set_present(slot,false);
        }
        // n can equal capacity, in which case head remains unchanged.
        if n < self.bytes.len() {
            self.head = self.index(n);
        }
        self.base = next;
        Ok(())
    }
}

/// A TLS Handshake structure (RFC 8446 §4). `kind` is intentionally not treated
/// as evidence of a legal handshake transition or successful authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandshakeMessage<'a> {
    pub kind: u8,
    pub body: &'a [u8],
    pub encoded: &'a [u8],
}

/// Parse one raw TLS handshake message, not a TLS record. QUIC carries these
/// messages in CRYPTO frames. A caller-set body cap bounds large certificate data.
pub fn parse_message(
    input: &[u8],
    max_body: usize,
) -> Result<(HandshakeMessage<'_>, usize), Error> {
    if input.len() < 4 {
        return Err(Error::Truncated);
    }
    let len = ((input[1] as usize) << 16) | ((input[2] as usize) << 8) | input[3] as usize;
    if len > max_body {
        return Err(Error::MessageTooLarge);
    }
    let total = 4 + len;
    if input.len() < total {
        return Err(Error::Truncated);
    }
    Ok((
        HandshakeMessage {
            kind: input[0],
            body: &input[4..total],
            encoded: &input[..total],
        },
        total,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_bitmap_handles_partial_bytes_and_ring_wrap(){
        for capacity in 1..=33 {
            let mut data=[0;33];let mut bits=[0xaa;5];
            let mut b=CryptoBuffer::new(&mut data[..capacity],&mut bits[..bitmap_bytes(capacity)]).unwrap();
            for offset in 0..257u64 {
                b.insert(offset,&[offset as u8]).unwrap();assert_eq!(b.ready().0,&[offset as u8]);b.consume(1).unwrap();assert_eq!(b.ready_len(),0);
            }
        }
        assert!(matches!(CryptoBuffer::new(&mut[0;9],&mut[0;1]),Err(Error::InvalidStorage)));
        assert_eq!(bitmap_bytes(8192),1024);
    }

    #[test]
    fn reorder_duplicate_and_wrap() {
        let mut bytes = [0; 8];
        let mut bitmap = [9; 8];
        let mut b = CryptoBuffer::new(&mut bytes, &mut bitmap).unwrap();
        b.insert(4, b"efgh").unwrap();
        assert_eq!(b.ready_len(), 0);
        b.insert(0, b"abcd").unwrap();
        b.insert(2, b"cdef").unwrap();
        assert_eq!(b.ready(), (&b"abcdefgh"[..], &b""[..]));
        b.consume(6).unwrap();
        b.insert(8, b"ijklmn").unwrap();
        assert_eq!(b.ready(), (&b"gh"[..], &b"ijklmn"[..]));
        b.consume(8).unwrap();
        assert_eq!(b.consumed(), 14);
        b.insert(14, b"op").unwrap();
        assert_eq!(b.ready().0, b"op");
    }

    #[test]
    fn insertion_errors_are_transactional() {
        let mut bytes = [0; 8];
        let mut bitmap = [0; 8];
        let mut b = CryptoBuffer::new(&mut bytes, &mut bitmap).unwrap();
        b.insert(3, b"d").unwrap();
        assert_eq!(b.insert(0, b"abcX"), Err(Error::ConflictingOverlap));
        assert_eq!(b.ready_len(), 0);
        assert_eq!(b.insert(0, b"123456789"), Err(Error::BufferExceeded));
        b.insert(0, b"abc").unwrap();
        assert_eq!(b.ready().0, b"abcd");
        assert_eq!(b.consume(5), Err(Error::ConsumeBeyondReady));
        assert_eq!(b.ready().0, b"abcd");
        assert_eq!(b.insert(MAX_OFFSET, b"x"), Err(Error::OffsetOverflow));
    }

    #[test]
    fn consumed_retransmissions_never_reenter_transcript() {
        let mut bytes = [0; 4];
        let mut bitmap = [0; 4];
        let mut b = CryptoBuffer::new(&mut bytes, &mut bitmap).unwrap();
        b.insert(0, b"abcd").unwrap();
        b.consume(4).unwrap();
        b.insert(0, b"xxxx").unwrap();
        assert_eq!(b.ready_len(), 0);
        b.insert(2, b"xxef").unwrap();
        assert_eq!(b.ready().0, b"ef");
    }

    #[test]
    fn window_can_process_unbounded_cumulative_input() {
        let mut bytes = [0; 7];
        let mut bitmap = [0; 7];
        let mut b = CryptoBuffer::new(&mut bytes, &mut bitmap).unwrap();
        for offset in 0..10000 {
            b.insert(offset, &[offset as u8]).unwrap();
            assert_eq!(b.ready().0, &[offset as u8]);
            b.consume(1).unwrap();
        }
        assert_eq!(b.consumed(), 10000);
    }

    #[test]
    fn tls_framing_rejects_truncation_and_bound() {
        let input = [1, 0, 0, 3, 4, 5, 6, 99];
        let (msg, n) = parse_message(&input, 3).unwrap();
        assert_eq!(n, 7);
        assert_eq!(msg.kind, 1);
        assert_eq!(msg.body, &[4, 5, 6]);
        for len in 0..7 {
            assert_eq!(parse_message(&input[..len], 3), Err(Error::Truncated));
        }
        assert_eq!(parse_message(&input, 2), Err(Error::MessageTooLarge));
        assert_eq!(parse_message(&[20, 0, 0, 0], 0).unwrap().1, 4);
    }
}
