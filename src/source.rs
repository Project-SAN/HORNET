use alloc::vec::Vec;
use crate::types::{Ahdr, Chdr, Error, Exp, Nonce, Result, Si, Fs};

pub struct Session {
    pub ahdr_f: Ahdr,
    pub ahdr_b: Ahdr,
}

pub fn initialize_session(_keys_f: &[Si], _fses_f: &[Fs], _keys_b: &[Si], _fses_b: &[Fs], rmax: usize) -> Result<Session> {
    let ahdr_f = crate::ahdr::create_ahdr(_keys_f, _fses_f, rmax)?;
    let ahdr_b = crate::ahdr::create_ahdr(_keys_b, _fses_b, rmax)?;
    Ok(Session { ahdr_f, ahdr_b })
}

pub fn build_data_packet(_chdr: &Chdr, _ahdr: &Ahdr, _iv0: Nonce, _payload: &mut [u8]) -> Result<()> {
    // TODO: onion-encrypt payload with forward keys per Alg.19
    Err(Error::NotImplemented)
}

