//! Focused execution of the production bounded prefix assembler. The full
//! Path/Recovery/key-owner submission tests remain in path_owner/tests.rs.
//! Reusing this source here avoids instantiating unrelated owner projections.
use hibana_quic::roles::path_owner::{Error, PREFERRED_ADVERTISEMENT_BYTES, PreferredLocal};
use hibana_quic::{migration, parameters, tls_wire};
#[path = "../src/roles/path_owner/advertisement.rs"]
mod advertisement;
use hibana_quic::connection_id::{Cid, ResetToken};

fn expected() -> PreferredLocal {
    PreferredLocal {
        address: "127.0.0.1:4444".parse().unwrap(),
        cid: Cid::new(b"prefcid1").unwrap(),
        reset_token: ResetToken::new([9; 16]),
    }
}
fn message(preferred: PreferredLocal, dual: bool) -> Vec<u8> {
    let mut value = [0u8; 49];
    if let std::net::SocketAddr::V4(address) = preferred.address {
        value[..4].copy_from_slice(&address.ip().octets());
        value[4..6].copy_from_slice(&address.port().to_be_bytes());
    } else {
        panic!("fixture IPv4");
    }
    if dual {
        value[6..22].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        value[22..24].copy_from_slice(&4444u16.to_be_bytes());
    }
    value[24] = 8;
    value[25..33].copy_from_slice(preferred.cid.as_bytes());
    value[33..].copy_from_slice(preferred.reset_token.as_bytes());
    let mut parameters = vec![0, 8];
    parameters.extend_from_slice(b"clientid");
    parameters.extend_from_slice(&[15, 8]);
    parameters.extend_from_slice(b"serverid");
    parameters.extend_from_slice(&[13, 49]);
    parameters.extend_from_slice(&value);
    let mut output = vec![0; 256];
    let len = tls_wire::encode_encrypted_extensions(&mut output, tls_wire::ALPN, &parameters).unwrap();
    output.truncate(len);
    output
}
#[test]
fn split_reordered_and_duplicate_prefix_never_fills_a_hole() {
    let expected = expected();
    let message = message(expected, false);
    let mut evidence = advertisement::Evidence::new();
    assert!(!evidence.accept(4, &message[4..], expected).unwrap());
    assert!(!evidence.accept(2, &message[2..4], expected).unwrap());
    assert!(!evidence.accept(2, &message[2..], expected).unwrap());
    assert!(!evidence.accept(0, &message[..1], expected).unwrap());
    assert!(evidence.accept(1, &message[1..2], expected).unwrap());
    assert!(evidence.accept(0, &message, expected).unwrap());
}
#[test]
fn each_split_point_requires_both_fragments() {
    let expected = expected();
    let message = message(expected, false);
    for split in 1..message.len() {
        let mut evidence = advertisement::Evidence::new();
        assert!(!evidence.accept(0, &message[..split], expected).unwrap());
        assert!(evidence.accept(split, &message[split..], expected).unwrap());
    }
}
#[test]
fn exact_preferred_cid_token_address_and_single_family_are_required() {
    let expected = expected();
    let mut wrong = [expected; 3];
    wrong[0].cid = Cid::new(b"wrongcid").unwrap();
    wrong[1].reset_token = ResetToken::new([10; 16]);
    wrong[2].address = "127.0.0.1:4445".parse().unwrap();
    for (actual, dual) in wrong
        .into_iter()
        .map(|p| (p, false))
        .chain([(expected, true)])
    {
        let mut evidence = advertisement::Evidence::new();
        assert_eq!(
            evidence.accept(0, &message(actual, dual), expected),
            Err(Error::InvalidAdvertisement)
        );
    }
}
#[test]
fn conflicting_overlap_does_not_overwrite_prior_accepted_bytes() {
    let expected = expected();
    let message = message(expected, false);
    let mut evidence = advertisement::Evidence::new();
    assert!(!evidence.accept(4, &message[4..], expected).unwrap());
    let mut changed = message[4..].to_vec();
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(
        evidence.accept(4, &changed, expected),
        Err(Error::InvalidAdvertisement)
    );
    assert!(evidence.accept(0, &message[..4], expected).unwrap());
}
#[test]
fn bounded_prefix_rejects_wrong_type_and_oversize_and_ignores_following_messages() {
    let expected = expected();
    assert_eq!(
        advertisement::Evidence::new().accept(0, &[8, 0, 0x10, 0], expected),
        Err(Error::Capacity)
    );
    assert_eq!(
        advertisement::Evidence::new().accept(0, &[11, 0, 0, 0], expected),
        Err(Error::InvalidAdvertisement)
    );
    assert_eq!(
        advertisement::Evidence::new().accept(PREFERRED_ADVERTISEMENT_BYTES, &[1], expected),
        Err(Error::Capacity)
    );
    let mut bytes = message(expected, false);
    bytes.extend_from_slice(&[11, 0, 0, 0]);
    assert!(
        advertisement::Evidence::new()
            .accept(0, &bytes, expected)
            .unwrap()
    );
}
#[test]
fn clearing_evidence_removes_all_coverage() {
    let expected = expected();
    let message = message(expected, false);
    let mut evidence = advertisement::Evidence::new();
    assert!(!evidence.accept(0, &message[..8], expected).unwrap());
    evidence.clear();
    assert!(!evidence.accept(8, &message[8..], expected).unwrap());
    assert!(evidence.accept(0, &message[..8], expected).unwrap());
}
