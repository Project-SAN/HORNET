use alloc::vec::Vec;
use alloc::vec;
use rand_core::RngCore;
use crate::crypto::{kdf::{hop_key, OpLabel}, mac, prg};
use crate::fs;
use crate::types::{Ahdr, Error, Exp, Fs, Result, RoutingSegment, Si, Sv, C_BLOCK, FS_LEN, K_MAC};

pub struct ProcResult {
    pub s: Si,
    pub r: RoutingSegment,
    pub ahdr_next: Ahdr,
}

// Algorithm 3: Process an AHDR at a hop
pub fn proc_ahdr(sv: &Sv, ahdr: &Ahdr, now: Exp) -> Result<ProcResult> {
    let rc = ahdr.bytes.len();
    if rc % C_BLOCK != 0 { return Err(Error::Length); }
    let r = rc / C_BLOCK;
    // Parse head block
    let head = &ahdr.bytes[0..C_BLOCK];
    let fs_bytes = &head[0..FS_LEN];
    let gamma = &head[FS_LEN..C_BLOCK];
    let beta = &ahdr.bytes[C_BLOCK..];
    let fs = Fs(<[u8; FS_LEN]>::try_from(fs_bytes).map_err(|_| Error::Length)?);
    let (s, rseg, exp) = fs::fs_open(sv, &fs)?;
    if now.0 >= exp.0 { return Err(Error::Expired); }
    // Verify MAC: gamma == MAC(hMAC(s); FS || beta)
    let mut mac_key = [0u8; 16];
    hop_key(&s.0, OpLabel::Mac, &mut mac_key);
    let mut mac_input = Vec::with_capacity(FS_LEN + beta.len());
    mac_input.extend_from_slice(&fs.0);
    mac_input.extend_from_slice(beta);
    let tag = mac::mac_trunc16(&mac_key, &mac_input);
    if &tag.0 != gamma { return Err(Error::InvalidMac); }
    // Compute next header: (beta || 0^c) XOR PRG2(s)
    let mut next = Vec::with_capacity(rc);
    next.extend_from_slice(beta);
    next.resize(rc, 0u8);
    let mut mask = vec![0u8; rc];
    prg::prg2(&s.0, &mut mask);
    for (b, m) in next.iter_mut().zip(mask.iter()) { *b ^= *m; }
    Ok(ProcResult { s, r: rseg, ahdr_next: Ahdr { bytes: next } })
}

// Algorithm 4: Create AHDR from {si},{FSi}
pub fn create_ahdr(keys: &[Si], fses: &[Fs], rmax: usize, rng: &mut dyn RngCore) -> Result<Ahdr> {
    let l = keys.len();
    if l == 0 || l != fses.len() { return Err(Error::Length); }
    if rmax == 0 || l > rmax { return Err(Error::Length); }
    let rc = rmax * C_BLOCK;
    // Compute paddings phi
    let mut phi: Vec<u8> = Vec::new(); // length i*c at step i
    for i in 0..(l.saturating_sub(1)) {
        let mut mask = vec![0u8; rc];
        prg::prg2(&keys[i].0, &mut mask);
        let start = (rmax - 1 - i) * C_BLOCK;
        let end = rc;
        let slice = &mask[start..end]; // length (i+1)*c
        // new_phi = (phi || 0^c) XOR slice
        let mut new_phi = Vec::with_capacity(phi.len() + C_BLOCK);
        new_phi.extend_from_slice(&phi);
        new_phi.resize(phi.len() + C_BLOCK, 0);
        for (b, m) in new_phi.iter_mut().zip(slice.iter()) { *b ^= *m; }
        phi = new_phi;
    }
    // beta_{l-1} = RAND((r-l)c) || phi
    let mut beta = Vec::with_capacity((rmax - 1) * C_BLOCK);
    let rand_len = (rmax - l) * C_BLOCK;
    if rand_len > 0 {
        let mut rnd = vec![0u8; rand_len];
        rng.fill_bytes(&mut rnd);
        beta.extend_from_slice(&rnd);
    }
    beta.extend_from_slice(&phi);
    // gamma_{l-1}
    let mut hkey = [0u8; 16];
    hop_key(&keys[l - 1].0, OpLabel::Mac, &mut hkey);
    let mut mac_input = Vec::with_capacity(FS_LEN + beta.len());
    mac_input.extend_from_slice(&fses[l - 1].0);
    mac_input.extend_from_slice(&beta);
    let mut gamma = mac::mac_trunc16(&hkey, &mac_input).0.to_vec();
    // iterate i = l-2 .. 0
    for i in (0..=(l - 1).saturating_sub(1)).rev() {
        // base = FSi+1 || gamma_{i+1} || beta_{i+1}[0..(r-2)c]
        let mut base = Vec::with_capacity((rmax - 1) * C_BLOCK);
        base.extend_from_slice(&fses[i + 1].0);
        base.extend_from_slice(&gamma);
        let tail_len = (rmax - 2) * C_BLOCK;
        base.extend_from_slice(&beta[0..tail_len.min(beta.len())]);
        // mask = PRG2(s_i)[0..(r-1)c]
        let mut mask = vec![0u8; (rmax - 1) * C_BLOCK];
        prg::prg2(&keys[i].0, &mut mask);
        // beta_i = base XOR mask
        for (b, m) in base.iter_mut().zip(mask.iter()) { *b ^= *m; }
        beta = base;
        // gamma_i = MAC(hMAC(s_i); FS_i || beta_i)
        let mut hkey_i = [0u8; 16];
        hop_key(&keys[i].0, OpLabel::Mac, &mut hkey_i);
        let mut mac_input_i = Vec::with_capacity(FS_LEN + beta.len());
        mac_input_i.extend_from_slice(&fses[i].0);
        mac_input_i.extend_from_slice(&beta);
        gamma = mac::mac_trunc16(&hkey_i, &mac_input_i).0.to_vec();
    }
    // Compose AHDR: FS0 || gamma0 || beta0
    let mut bytes = Vec::with_capacity(rc);
    bytes.extend_from_slice(&fses[0].0);
    bytes.extend_from_slice(&gamma);
    // beta length should be (r-1)c; ensure size
    if beta.len() != (rmax - 1) * C_BLOCK { beta.resize((rmax - 1) * C_BLOCK, 0); }
    bytes.extend_from_slice(&beta);
    Ok(Ahdr { bytes })
}

// Algorithm 5: Nested AHDR construction (outer includes inner)
pub fn create_nested_ahdr(_outer_keys: &[Si], _outer_fses: &[Fs], _inner: &Ahdr, _rmax: usize, _rng: &mut dyn RngCore) -> Result<Ahdr> {
    // TODO: Implement Algorithm 5 exactly. Placeholder to keep API stable.
    Err(Error::NotImplemented)
}
