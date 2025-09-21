use alloc::vec::Vec;
use alloc::vec;
use crate::crypto::{kdf::{hop_key, OpLabel}, mac, prg};
use crate::types::{Error, Fs, Result, Si, Mac, C_BLOCK};

// Placeholders for Algorithm 1 and 2 from the paper.

pub struct FsPayload {
    pub bytes: Vec<u8>, // fixed length: r * c
    pub rmax: usize,
}

impl FsPayload {
    pub fn new_with_seed(rmax: usize, seed: &[u8; 16]) -> Self {
        let mut bytes = vec![0u8; rmax * C_BLOCK];
        // Initial payload P = PRG1(hPRG1(seed))
        prg::prg1(seed, &mut bytes);
        Self { bytes, rmax }
    }
}

// Alg.1: Add FS into FS payload
pub fn add_fs_into_payload(s: &Si, fs: &Fs, payload: &mut FsPayload) -> Result<Mac> {
    let rc = payload.bytes.len();
    // Ptmp = FS || Pin[0 .. (r-1)c] XOR PRG0(hPRG0(s))[k .. end]
    let ptmp_len = rc - crate::types::K_MAC; // |FS| + (r-1)c
    let mut ptmp = Vec::with_capacity(ptmp_len);
    ptmp.extend_from_slice(&fs.0);
    let pin_prefix_len = rc - C_BLOCK; // (r-1)c
    ptmp.extend_from_slice(&payload.bytes[0..pin_prefix_len]);
    // mask starting at offset k of an rc-long PRG stream
    let mut mask_full = vec![0u8; rc];
    prg::prg0(&s.0, &mut mask_full);
    for (b, m) in ptmp.iter_mut().zip(mask_full[crate::types::K_MAC..].iter()) { *b ^= *m; }
    // α = MAC(hMAC(s); Ptmp)
    let mut hkey = [0u8; 16];
    hop_key(&s.0, OpLabel::Mac, &mut hkey);
    let alpha = mac::mac_trunc16(&hkey, &ptmp);
    // Pout = α || Ptmp
    payload.bytes.clear();
    payload.bytes.extend_from_slice(&alpha.0);
    payload.bytes.extend_from_slice(&ptmp);
    Ok(alpha)
}

// Alg.2: Retrieve FSes from FS payload
pub fn retrieve_fses(keys: &[Si], init_seed: &[u8; 16], payload: &FsPayload) -> Result<Vec<Fs>> {
    let rc = payload.bytes.len();
    let l = keys.len();
    if l == 0 { return Ok(Vec::new()); }
    // Pinit = PRG1(hPRG1(seed))
    let mut pinit = vec![0u8; rc];
    prg::prg1(init_seed, &mut pinit);
    // ψ construction per Alg.2 line 3
    let mut psi = pinit[(payload.rmax - l) * C_BLOCK .. rc].to_vec(); // length l*c
    for t in 0..(l.saturating_sub(1)) {
        let start = (payload.rmax - l + 1 + t) * C_BLOCK;
        let mut mask_full = vec![0u8; rc];
        prg::prg0(&keys[t].0, &mut mask_full);
        let slice = &mask_full[start..rc];
        let mut m = vec![0u8; l * C_BLOCK];
        // place slice at beginning, then zeros padding of (t+1)c
        let copy_len = core::cmp::min(m.len().saturating_sub((t + 1) * C_BLOCK), slice.len());
        m[0..copy_len].copy_from_slice(&slice[0..copy_len]);
        for (a, b) in psi.iter_mut().zip(m.iter()) { *a ^= *b; }
    }
    // Pfull = P || ψ
    let mut pfull = Vec::with_capacity(rc + (l - 1) * C_BLOCK);
    pfull.extend_from_slice(&payload.bytes);
    pfull.extend_from_slice(&psi[0..(l - 1) * C_BLOCK]);
    // Recover FSes in reverse
    let mut fses_rev: Vec<Fs> = Vec::with_capacity(l);
    for i in (0..l).rev() {
        // check MAC on window [0..rc)
        let mut hkey = [0u8; 16];
        hop_key(&keys[i].0, OpLabel::Mac, &mut hkey);
        let alpha = &pfull[0..crate::types::K_MAC];
        let rest = &pfull[crate::types::K_MAC .. rc];
        let expected = mac::mac_trunc16(&hkey, rest);
        if expected.0 != *alpha { return Err(Error::InvalidMac); }
        // unmask: Pfull ^= PRG0(si) || 0^{(i+1)c}
        let mut mask_rc = vec![0u8; rc];
        prg::prg0(&keys[i].0, &mut mask_rc);
        for j in 0..rc { pfull[j] ^= mask_rc[j]; }
        // extract FS_i
        let mut fs_bytes = [0u8; crate::types::FS_LEN];
        fs_bytes.copy_from_slice(&pfull[crate::types::K_MAC .. crate::types::K_MAC + crate::types::FS_LEN]);
        fses_rev.push(Fs(fs_bytes));
        // shift window
        pfull.drain(0..C_BLOCK);
        // extend zeros to keep length?
        // We already appended enough psi above for all iterations
    }
    fses_rev.reverse();
    Ok(fses_rev)
}
