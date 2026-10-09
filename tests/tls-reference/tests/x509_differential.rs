//! Independent Rustls/ring verification oracle for public signed certificates.
//! Bounded mutation coverage, not proof of the full PKIX language or security.
use hibana_tls::x509::{name::Identity, verify};
use rustls::{RootCertStore,client::{WebPkiServerVerifier,danger::ServerCertVerifier}};
use rustls_pki_types::{CertificateDer,ServerName,UnixTime};
use std::{sync::Arc,time::Duration};
const ROOT:&[u8]=include_bytes!("../../vectors/certificates/root.der");
const CA:&[u8]=include_bytes!("../../vectors/certificates/intermediate.der");
const LEAF:&[u8]=include_bytes!("../../vectors/certificates/leaf.der");
#[test]
fn no_single_bit_leaf_mutation_is_accepted_against_reference_rejection(){
    let mut roots=RootCertStore::empty();roots.add(CertificateDer::from(ROOT)).unwrap();
    let oracle=WebPkiServerVerifier::builder_with_provider(Arc::new(roots),Arc::new(rustls::crypto::ring::default_provider())).build().unwrap();
    let now=UnixTime::since_unix_epoch(Duration::from_secs(1800000000));
    let name=ServerName::try_from("localhost").unwrap();
    let reference=|leaf:&[u8]|oracle.verify_server_cert(&CertificateDer::from(leaf),&[CertificateDer::from(CA)],&name,&[],now).is_ok();
    let owned=|leaf:&[u8]|verify::server(leaf,&[CA],&[ROOT],Identity::Dns("localhost"),1800000000).is_ok();
    assert!(reference(LEAF));assert!(owned(LEAF));
    for index in 0..LEAF.len(){
        for bit in 0..8 {
            let mut mutated=LEAF.to_vec();mutated[index]^=1<<bit;
            let actual=owned(&mutated);
            let expected=reference(&mutated);
            assert!(!actual || expected,"owned accepted reference-rejected mutation byte={index} bit={bit}");
        }
    }
}
