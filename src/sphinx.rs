// Minimal Sphinx skeleton for setup phase key agreement and FS collection.
use alloc::vec::Vec;
use crate::crypto::dh::DhKeyPair;
use crate::crypto::kdf::{hop_key, OpLabel};
use crate::types::{Result, Si};
use alloc::vec;
use crate::crypto::prg;

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

// GEN_SPHX_PL_SEND: Onion-wrap SHDRb so that each forward hop removes one PRG1 layer
pub fn gen_sphx_pl_send(keys_f: &[Si], shdr_b: &SphinxHeader) -> SphinxPayload {
    let mut buf = shdr_b.epub.to_vec();
    for i in 0..keys_f.len() {
        let mut mask = vec![0u8; buf.len()];
        prg::prg1(&keys_f[i].0, &mut mask);
        for (b, m) in buf.iter_mut().zip(mask.iter()) { *b ^= *m; }
    }
    SphinxPayload(buf)
}

// PROC_SPHX_PKT (forward): node removes its PRG1 layer and returns s_i
pub fn proc_sphx_pkt_forward(shdr: &SphinxHeader, sp: &mut SphinxPayload, node_secret: &[u8; 32]) -> Si {
    let si = derive_key_at_node(shdr, node_secret);
    let mut mask = vec![0u8; sp.0.len()];
    prg::prg1(&si.0, &mut mask);
    for (b, m) in sp.0.iter_mut().zip(mask.iter()) { *b ^= *m; }
    si
}

// GEN_SPHX_PL_RECV: start from plaintext payload bytes (e.g., Pf), D sends SPb
pub fn gen_sphx_pl_recv(plain: &[u8]) -> SphinxPayload { SphinxPayload(plain.to_vec()) }

// PROC_SPHX_PKT (backward): node adds its PRG1 layer (so source removes all at the end)
pub fn proc_sphx_pkt_backward(shdr: &SphinxHeader, sp: &mut SphinxPayload, node_secret: &[u8; 32]) -> Si {
    let si = derive_key_at_node(shdr, node_secret);
    let mut mask = vec![0u8; sp.0.len()];
    prg::prg1(&si.0, &mut mask);
    for (b, m) in sp.0.iter_mut().zip(mask.iter()) { *b ^= *m; }
    si
}

// UNWRAP_SPHX_PL_RECV at source: remove all backward layers using {s_bi}
pub fn unwrap_sphx_pl_recv(keys_b: &[Si], sp: &SphinxPayload) -> Vec<u8> {
    let mut buf = sp.0.clone();
    for i in 0..keys_b.len() {
        let mut mask = vec![0u8; buf.len()];
        prg::prg1(&keys_b[i].0, &mut mask);
        for (b, m) in buf.iter_mut().zip(mask.iter()) { *b ^= *m; }
    }
    buf
}
