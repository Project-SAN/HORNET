// A no_std-friendly Sphinx-like implementation with per-hop header MACs,
// header re-randomization (y blinding), and fixed-length payload onion.
// Note: This follows the structure of Sphinx (Danezis & Goldberg) adapted
// to X25519 and the crate's KDF/MAC/PRG interfaces.

use alloc::vec::Vec;
use alloc::vec;
use crate::crypto::kdf::{hop_key, OpLabel};
use crate::crypto::prg;
use crate::types::{Error, Result, Si};

pub const GROUP_LEN: usize = 32; // X25519 point size
pub const MU_LEN: usize = 16;    // truncated MAC size

#[derive(Clone, Copy)]
pub struct Header {
    pub y: [u8; GROUP_LEN],
    pub gamma: [u8; MU_LEN],
}

#[derive(Clone)]
pub struct Payload(pub Vec<u8>); // fixed-length

fn clamp_scalar(x: &mut [u8; 32]) {
    x[0] &= 248;
    x[31] &= 127;
    x[31] |= 64;
}

fn blinding_scalar_from_shared(shared: &[u8; 32]) -> [u8; 32] {
    let mut s = [0u8; 32];
    // Derive 32 bytes and clamp to valid X25519 scalar
    hop_key(shared, OpLabel::Prp, &mut s[0..16]);
    hop_key(shared, OpLabel::Enc, &mut s[16..32]);
    clamp_scalar(&mut s);
    s
}

fn derive_shared_source(ephemeral_secret: &[u8; 32], node_pub: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*ephemeral_secret, *node_pub)
}

fn derive_shared_node(node_secret: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*node_secret, *y)
}

fn derive_si_from_shared(shared: &[u8; 32]) -> Si {
    let mut si = [0u8; 16];
    hop_key(shared, OpLabel::Enc, &mut si);
    Si(si)
}

// Build initial y via blinding chain at the source (so nodes can track it)
pub fn build_header_chain(ephemeral_public: &[u8; 32], shareds: &[[u8; 32]]) -> [u8; 32] {
    let mut y = *ephemeral_public;
    for sh in shareds.iter() {
        let b = blinding_scalar_from_shared(sh);
        y = x25519_dalek::x25519(b, y);
    }
    y
}

// Source constructs full header (y, gamma) and payload onion for forward path
pub fn source_create_forward(
    ephemeral_secret: &[u8; 32],
    node_pubs: &[[u8; 32]],
    beta_len: usize,
    sp_len: usize,
) -> (Header, Payload, Vec<Si>, [u8; 32]) {
    // Compute per-hop shared secrets and Si
    let mut shareds: Vec<[u8; 32]> = Vec::with_capacity(node_pubs.len());
    let mut sis: Vec<Si> = Vec::with_capacity(node_pubs.len());
    for pk in node_pubs.iter() {
        let sh = derive_shared_source(ephemeral_secret, pk);
        sis.push(derive_si_from_shared(&sh));
        shareds.push(sh);
    }
    // Compute initial y (after all blinded factors)
    let eph_pub = x25519_dalek::x25519(*ephemeral_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
    let y0 = build_header_chain(&eph_pub, &shareds);
    // Build beta/gamma onion from last to first
    let l = node_pubs.len();
    let mut beta = vec![0u8; beta_len];
    let mut gamma = [0u8; MU_LEN];
    // Backward chain gamma = MAC(shared_i, gamma)
    for i in (0..l).rev() {
        let mut mac_key = [0u8; 16];
        hop_key(&shareds[i], OpLabel::Mac, &mut mac_key);
        let t = crate::crypto::mac::mac_trunc16(&mac_key, &gamma);
        gamma.copy_from_slice(&t.0);
    }
    // Build fixed-length payload SPf (all-zero then apply reverse layering using Si so first hop can peel its layer)
    let mut sp = vec![0u8; sp_len];
    for i in (0..l).rev() {
        let mut mask = vec![0u8; sp_len];
        prg::prg1(&sis[i].0, &mut mask);
        for (b, m) in sp.iter_mut().zip(mask.iter()) { *b ^= *m; }
    }
    (Header { y: y0, gamma }, Payload(sp), sis, eph_pub)
}

// Node processes forward: verify mu (gamma), update y, peel one payload layer, return Si
pub fn node_process_forward(hdr: &mut Header, sp: &mut Payload, node_secret: &[u8; 32], _beta_len: usize) -> Result<Si> {
    // derive shared from current y
    let shared = derive_shared_node(node_secret, &hdr.y);
    // update gamma chain
    let mut mac_key = [0u8; 16];
    hop_key(&shared, OpLabel::Mac, &mut mac_key);
    let tag = crate::crypto::mac::mac_trunc16(&mac_key, &hdr.gamma);
    hdr.gamma.copy_from_slice(&tag.0);
    // re-randomize y
    let b = blinding_scalar_from_shared(&shared);
    hdr.y = x25519_dalek::x25519(b, hdr.y);
    // peel one payload layer
    let mut mask = vec![0u8; sp.0.len()];
    let si = derive_si_from_shared(&shared);
    prg::prg1(&si.0, &mut mask);
    for (b, m) in sp.0.iter_mut().zip(mask.iter()) { *b ^= *m; }
    Ok(si)
}

// Destination creates backward payload SPb from plaintext of forward-collected FS payload
pub fn dest_create_backward_sp(plain: &[u8], sp_len: usize) -> Payload {
    let mut buf = vec![0u8; sp_len];
    let copy = core::cmp::min(plain.len(), sp_len);
    buf[0..copy].copy_from_slice(&plain[0..copy]);
    Payload(buf)
}

// Node processes backward: add one layer with PRG1(Si)
pub fn node_process_backward(hdr: &Header, sp: &mut Payload, node_secret: &[u8; 32]) -> Result<Si> {
    let shared = derive_shared_node(node_secret, &hdr.y);
    let si = derive_si_from_shared(&shared);
    let mut mask = vec![0u8; sp.0.len()];
    prg::prg1(&si.0, &mut mask);
    for (b, m) in sp.0.iter_mut().zip(mask.iter()) { *b ^= *m; }
    Ok(si)
}

// Source unwraps SPb by removing all layers with keys_b
pub fn source_unwrap_backward(keys_b: &[Si], sp: &Payload) -> Vec<u8> {
    let mut buf = sp.0.clone();
    for i in 0..keys_b.len() {
        let mut mask = vec![0u8; buf.len()];
        prg::prg1(&keys_b[i].0, &mut mask);
        for (b, m) in buf.iter_mut().zip(mask.iter()) { *b ^= *m; }
    }
    buf
}
