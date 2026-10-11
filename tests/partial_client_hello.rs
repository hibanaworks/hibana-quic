//! Framing regression from the authenticated Initial ranges in runner
//! 37434925514. This is synthetic data with the observed lengths, not captured
//! TLS material and not a claim to replay a full encrypted connection.
use hibana_quic::quic::buffer::CryptoBuffer;
use hibana_quic::quic::buffer::Error;
use hibana_quic::quic::buffer::bitmap_bytes;
use hibana_quic::quic::buffer::parse_message;

#[test]
fn repeated_initial_prefix_does_not_complete_a_missing_client_hello_tail() {
    const TOTAL: usize = 1490;
    const PREFIX: usize = 1133;
    let mut message = [0x5a; TOTAL];
    message[..4].copy_from_slice(&[1, 0, 5, 206]); // ClientHello body length1486.
    let mut bytes = [0; TOTAL];
    let mut present = [0; bitmap_bytes(TOTAL)];
    let mut crypto = CryptoBuffer::new(&mut bytes, &mut present).unwrap();

    // Server-side capture contained prefix PN0, repeated prefix PN3 and a
    // PING PN6; none supplies the missing offset1133/length357 range.
    for _ in 0..2 {
        crypto.insert(0, &message[..PREFIX]).unwrap();
        assert_eq!(crypto.ready_len(), PREFIX);
        assert_eq!(crypto.consumed(), 0);
        assert_eq!(
            parse_message(crypto.ready().0, TOTAL),
            Err(Error::Truncated)
        );
    }
    // No insert for PING: acknowledging its packet cannot mint CRYPTO bytes.
    assert_eq!(crypto.ready_len(), PREFIX);
    assert_eq!(
        parse_message(crypto.ready().0, TOTAL),
        Err(Error::Truncated)
    );

    // Only actual delivery of the missing range permits framing to complete.
    crypto.insert(PREFIX as u64, &message[PREFIX..]).unwrap();
    let (framed, count) = parse_message(crypto.ready().0, TOTAL).unwrap();
    assert_eq!(framed.kind, 1);
    assert_eq!(framed.encoded, message);
    assert_eq!(count, TOTAL);
    crypto.consume(count).unwrap();
    assert_eq!(crypto.consumed(), TOTAL as u64);
    assert_eq!(crypto.ready_len(), 0);
}
