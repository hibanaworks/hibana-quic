//! Shared no-heap exercised paths for allocation counting and target link smoke.
//! No TLS handshake, network endpoint, or hardware execution is represented.
use hibana_quic::crypto::{
    CipherSuite, IntegrityBudget, KeyKind, PacketKey, initial_keys, retry_integrity_tag,
    verify_retry,
};

#[path = "certificate_smoke.rs"]
mod certificate_smoke;

pub fn exercise() {
    certificate_smoke::exercise();
    // Test-only supplied traffic secret: this helper is never an endpoint or TLS
    // backend. Production keys must come from authenticated TLS traffic secrets.
    let secret = core::hint::black_box([0x51; 32]);
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        let mut write = PacketKey::from_secret(suite, KeyKind::OneRtt, &secret).unwrap();
        let mut read = PacketKey::from_secret(suite, KeyKind::OneRtt, &secret).unwrap();
        let mut budget = IntegrityBudget::new();
        for pn in 0..2 {
            let mut packet = [0; 64];
            packet[0] = 0x40;
            packet[1] = pn as u8;
            packet[2..7].copy_from_slice(b"hello");
            let (header, body) = packet.split_at_mut(2);
            let n = write.seal(pn, header, body, 5).unwrap();
            let total = n + 2;
            write.protect_header(&mut packet[..total], 1).unwrap();
            assert_eq!(read.unprotect_header(&mut packet[..total], 1).unwrap(), 1);
            let (header, body) = packet[..total].split_at_mut(2);
            assert_eq!(read.open(pn, header, body, &mut budget).unwrap(), 5);
            assert_eq!(&body[..5], b"hello");
            write.update_key().unwrap();
            read.update_key().unwrap();
        }
        write.discard();
        read.discard();
    }
    let mut keys = initial_keys(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    core::hint::black_box(keys.client.header_mask(&[1; 16]).unwrap());
    keys.client.discard();
    keys.server.discard();
    let mut scratch = [0; 64];
    let mut retry = [0; 24];
    retry[..8].copy_from_slice(b"retryhdr");
    let tag = retry_integrity_tag(&[1, 2, 3], &retry[..8], &mut scratch).unwrap();
    retry[8..].copy_from_slice(&tag);
    verify_retry(&[1, 2, 3], &retry, &mut scratch).unwrap();
}
