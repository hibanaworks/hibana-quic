//! Immutable output of an actual owning actor's successful AEAD seal.
//! A caller-created Packet cannot stand in for this non-Clone provenance.
use super::packet_protection::{Descriptor, Packet};
use crate::crypto::KeyKind;
use core::ops::Deref;
use sha2::{Digest, Sha256};

pub struct SealedPacket<const N: usize> {
    packet: Packet<N>,
    descriptor: Descriptor,
    kind: KeyKind,
    plaintext_digest: [u8; 32],
}
impl<const N: usize> SealedPacket<N> {
    pub(crate) fn from_owner(
        packet: Packet<N>,
        descriptor: Descriptor,
        kind: KeyKind,
        plaintext_digest: [u8; 32],
    ) -> Self {
        Self {
            packet,
            descriptor,
            kind,
            plaintext_digest,
        }
    }
    pub const fn generation(&self) -> u64 {
        self.descriptor.generation
    }
    pub const fn operation_id(&self) -> u64 {
        self.descriptor.sequence
    }
    pub const fn kind(&self) -> KeyKind {
        self.kind
    }
    pub fn authenticates_plaintext(&self, plaintext: &[u8]) -> bool {
        self.plaintext_digest == plaintext_digest(plaintext)
    }
}
impl<const N: usize> Deref for SealedPacket<N> {
    type Target = Packet<N>;
    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}
pub(crate) fn plaintext_digest(plaintext: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"hibana-quic:packet-plaintext:v1\0");
    digest.update((plaintext.len() as u64).to_be_bytes());
    digest.update(plaintext);
    digest.finalize().into()
}
