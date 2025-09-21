// Minimal Sphinx skeleton for setup phase key agreement and FS collection.
use alloc::vec::Vec;
use crate::types::{Error, Result, Si, Fs};

pub struct SphinxHeader(pub Vec<u8>);
pub struct SphinxPayload(pub Vec<u8>);

pub struct SetupPacket {
    pub shdr: SphinxHeader,
    pub sp: SphinxPayload,
    pub p: Vec<u8>, // FS payload bytes
}

pub fn build_setup_packets(_lf: usize, _lb: usize, _rmax: usize) -> (SetupPacket, SetupPacket) {
    // TODO: construct SHDR/SP for forward/backward with empty P
    (
        SetupPacket { shdr: SphinxHeader(Vec::new()), sp: SphinxPayload(Vec::new()), p: Vec::new() },
        SetupPacket { shdr: SphinxHeader(Vec::new()), sp: SphinxPayload(Vec::new()), p: Vec::new() },
    )
}

pub fn process_at_node(_pkt: &mut SetupPacket) -> Result<(Si, Fs)> {
    // TODO: Sphinx processing to derive per-hop key and emit FS
    Err(Error::NotImplemented)
}

pub fn retrieve_fses_at_source(_pkt: &SetupPacket) -> Result<Vec<Fs>> {
    // TODO: unwrap SP and retrieve FS list from P
    Err(Error::NotImplemented)
}

