// Minimal Sphinx skeleton for setup phase key agreement and FS collection.
use alloc::vec::Vec;
use crate::crypto::dh::DhKeyPair;
use crate::crypto::kdf::{hop_key, OpLabel};
use crate::types::{Result, Si};

#[derive(Clone, Copy)]
pub struct SphinxHeader {
    pub epub: [u8; 32], // source ephemeral public key g^xS
}

#[derive(Clone)]
pub struct SphinxPayload(pub Vec<u8>);

#[derive(Clone)]
pub struct SetupPacket {
    pub shdr: SphinxHeader,
    pub sp: SphinxPayload,
    pub p: Vec<u8>, // FS payload bytes (carried outside SP in our layout)
}

// Source-side: derive per-hop symmetric keys for a path using the source ephemeral secret
pub fn derive_path_keys_at_source(ephemeral_secret: &[u8; 32], node_pubkeys: &[[u8; 32]]) -> Vec<Si> {
    node_pubkeys
        .iter()
        .map(|pk| {
            let shared = x25519_dalek::x25519(*ephemeral_secret, *pk);
            // Reduce to 16-byte Si via HKDF
            let mut si = [0u8; 16];
            hop_key(&shared, OpLabel::Enc, &mut si);
            Si(si)
        })
        .collect()
}

// Node-side: derive its symmetric key from Sphinx header and node static secret
pub fn derive_key_at_node(shdr: &SphinxHeader, node_secret: &[u8; 32]) -> Si {
    let shared = x25519_dalek::x25519(*node_secret, shdr.epub);
    let mut si = [0u8; 16];
    hop_key(&shared, OpLabel::Enc, &mut si);
    Si(si)
}

// Build minimal headers for forward/backward using the same ephemeral keypair
pub fn build_minimal_headers(ephemeral: &DhKeyPair) -> (SphinxHeader, SphinxHeader) {
    let sh = SphinxHeader { epub: ephemeral.public };
    (sh, sh)
}
