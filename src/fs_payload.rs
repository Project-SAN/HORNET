use alloc::vec::Vec;
use crate::types::{Error, Fs, Result, Si, Mac, C_BLOCK, R_MAX};

// Placeholders for Algorithm 1 and 2 from the paper.

pub struct FsPayload {
    pub bytes: Vec<u8>, // fixed length: r * c
}

impl FsPayload {
    pub fn new(r: usize) -> Self { Self { bytes: alloc::vec![0u8; r * C_BLOCK] } }
}

// Alg.1: Add FS into FS payload
pub fn add_fs_into_payload(_s: &Si, _fs: &Fs, _payload: &mut FsPayload) -> Result<Mac> {
    // TODO: implement encryption/padding per Algorithm 1
    Err(Error::NotImplemented)
}

// Alg.2: Retrieve FSes from FS payload
pub fn retrieve_fses(_keys: &[Si], _payload: &FsPayload) -> Result<alloc::vec::Vec<Fs>> {
    // TODO: implement per Algorithm 2
    Err(Error::NotImplemented)
}

