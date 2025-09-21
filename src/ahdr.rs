use alloc::vec::Vec;
use crate::types::{Ahdr, Error, Exp, Fs, Mac, Result, RoutingSegment, Si, Sv, C_BLOCK};

pub struct ProcResult {
    pub s: Si,
    pub r: RoutingSegment,
    pub ahdr_next: Ahdr,
}

// Algorithm 3: Process an AHDR at a hop
pub fn proc_ahdr(_sv: &Sv, _ahdr: &Ahdr, _now: Exp) -> Result<ProcResult> {
    // TODO: FS_OPEN(SV, FS), MAC verify, EXP check, shift+PRG2 pad
    Err(Error::NotImplemented)
}

// Algorithm 4: Create AHDR from {si},{FSi}
pub fn create_ahdr(_keys: &[Si], _fses: &[Fs], rmax: usize) -> Result<Ahdr> {
    let mut bytes = Vec::with_capacity(rmax * C_BLOCK);
    bytes.resize(rmax * C_BLOCK, 0);
    // TODO: implement onion construction reversing PROC_AHDR
    Ok(Ahdr { bytes })
}

// Algorithm 5: Nested AHDR construction (outer includes inner)
pub fn create_nested_ahdr(_outer_keys: &[Si], _outer_fses: &[Fs], _inner: &Ahdr, rmax: usize) -> Result<Ahdr> {
    let mut bytes = Vec::with_capacity(rmax * C_BLOCK);
    bytes.resize(rmax * C_BLOCK, 0);
    // TODO
    Ok(Ahdr { bytes })
}

