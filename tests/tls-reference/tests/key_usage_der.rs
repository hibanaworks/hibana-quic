// Independent retained RustCrypto DER parser; production does not depend on it.
use der::{Decode, Reader, Tag, TagNumber, Tagged, asn1::{AnyRef, BitStringRef, OctetStringRef}};
use hibana_tls::x509::key_usage::read as actual;
const MAX_EXTENSIONS: usize = 64;
fn reference_read_key_usage(certificate: &[u8]) -> der::Result<Option<BitStringRef<'_>>> {
    AnyRef::from_der(certificate)?.sequence(|certificate| {
        let tbs: AnyRef<'_> = certificate.decode()?;
        let _: AnyRef<'_> = certificate.decode()?;
        let _: BitStringRef<'_> = certificate.decode()?;
        tbs.sequence(|tbs| {
            let version = Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::N0,
            };
            if !tbs.is_finished() && tbs.peek_tag()? == version {
                let _: AnyRef<'_> = tbs.decode()?;
            }
            // serialNumber, signature, issuer, validity, subject, SPKI.
            for tag in [
                Tag::Integer,
                Tag::Sequence,
                Tag::Sequence,
                Tag::Sequence,
                Tag::Sequence,
                Tag::Sequence,
            ] {
                let value: AnyRef<'_> = tbs.decode()?;
                value.tag().assert_eq(tag)?;
            }
            if tbs.is_finished() {
                return Ok(None);
            }
            let extensions: AnyRef<'_> = tbs.decode()?;
            extensions.tag().assert_eq(Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::N3,
            })?;
            AnyRef::from_der(extensions.value())?.sequence(|extensions| {
                let mut usage = None;
                let mut count = 0;
                while !extensions.is_finished() {
                    count += 1;
                    if count > MAX_EXTENSIONS {
                        return Err(Tag::Sequence.value_error());
                    }
                    let extension: AnyRef<'_> = extensions.decode()?;
                    extension.sequence(|extension| {
                        let oid: AnyRef<'_> = extension.decode()?;
                        oid.tag().assert_eq(Tag::ObjectIdentifier)?;
                        if !extension.is_finished() && extension.peek_tag()? == Tag::Boolean {
                            let _: bool = extension.decode()?;
                        }
                        let value: OctetStringRef<'_> = extension.decode()?;
                        // id-ce-keyUsage, 2.5.29.15. OID value bytes, not a full TLV.
                        if oid.value() == [0x55, 0x1d, 0x0f] {
                            if usage.is_some() {
                                return Err(Tag::BitString.value_error());
                            }
                            usage = Some(BitStringRef::from_der(value.as_bytes())?);
                        }
                        Ok(())
                    })?;
                }
                Ok(usage)
            })
        })
    })
}

fn reference(bytes: &[u8]) -> Result<Option<u16>, ()> {
    let Some(usage) = reference_read_key_usage(bytes).map_err(|_| ())? else { return Ok(None); };
    if usage.is_empty() || usage.bit_len() > 9 || !usage.bits().any(|set| set) { return Err(()); }
    if let Some(last) = usage.raw_bytes().last() && usage.unused_bits() != 0
        && last & ((1u8 << usage.unused_bits()) - 1) != 0 { return Err(()); }
    let mut out = 0u16;
    for (i, set) in usage.bits().enumerate() { if set {out |= 1 << i;} }
    Ok(Some(out))
}
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {out.push(value.len() as u8);} else if value.len() < 256 {out.extend_from_slice(&[0x81, value.len() as u8]);} else {out.push(0x82);out.extend_from_slice(&(value.len() as u16).to_be_bytes());}
    out.extend_from_slice(value);out
}
fn extension(bits: &[u8], critical: Option<u8>) -> Vec<u8> {
    let mut value = tlv(6, &[0x55, 0x1d, 0x0f]);
    if let Some(c) = critical {value.extend(tlv(1, &[c]));}
    value.extend(tlv(4, &tlv(3, bits)));tlv(0x30, &value)
}
fn certificate(extensions: &[Vec<u8>]) -> Vec<u8> {
    let mut tbs = tlv(0xa0, &tlv(2, &[2]));tbs.extend(tlv(2, &[1]));
    for _ in 0..5 {tbs.extend(tlv(0x30, &[]));}
    if !extensions.is_empty() {tbs.extend(tlv(0xa3, &tlv(0x30, &extensions.concat())));}
    let mut cert = tlv(0x30, &tbs);cert.extend(tlv(0x30, &[]));cert.extend(tlv(3, &[0, 1]));tlv(0x30, &cert)
}
#[test]
fn usage_grammar_matches_independent_der_parser() {
    assert_eq!(actual(&certificate(&[]), 64), Ok(None));
    let mut count = 0;
    for unused in 0..=9 {
        for first in 0..=255u8 {
            for len in 0..=3 {
                let mut bits = vec![unused];bits.extend(std::iter::repeat_n(first, len));
                let cert = certificate(&[extension(&bits, Some(255))]);
                assert_eq!(actual(&cert, 64).map_err(|_| ()), reference(&cert), "unused={unused}, byte={first}, len={len}");
                count += 1;
            }
        }
    }
    assert_eq!(count, 10240);
}
#[test]
fn rejected_der_never_becomes_accepted_under_mutation() {
    for bits in [&[7, 0x80][..], &[2, 0x04][..], &[7, 0x80, 0x80][..]] {
        let cert = certificate(&[extension(bits, Some(255))]);
        assert_eq!(actual(&cert, 64).map_err(|_| ()), reference(&cert));
        for len in 0..cert.len() {assert!(actual(&cert[..len], 64).is_err());}
        for bit in 0..cert.len()*8 {
            let mut changed = cert.clone();changed[bit / 8] ^= 1 << (bit % 8);
            if let Ok(value) = actual(&changed, 64) {assert_eq!(reference(&changed), Ok(value), "bit {bit}");}
        }
    }
    let repeated = extension(&[7, 0x80], None);
    assert!(actual(&certificate(&[repeated.clone(), repeated]), 64).is_err());
    for critical in [1, 2, 127, 254] {assert!(actual(&certificate(&[extension(&[7, 0x80], Some(critical))]),64).is_err());}
    let unknown = tlv(0x30, &[0x06, 0x01, 0x2a, 0x04, 0x00]);
    assert_eq!(actual(&certificate(&vec![unknown.clone(); 64]),64), Ok(None));
    assert!(actual(&certificate(&vec![unknown; 65]),64).is_err());
}
