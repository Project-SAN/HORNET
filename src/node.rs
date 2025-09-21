use crate::types::{Ahdr, Chdr, Error, Exp, Result, RoutingSegment, Sv};

pub struct NodeCtx<'a> {
    pub sv: Sv,
    pub now: &'a dyn crate::time::TimeProvider,
    // User supplies a forwarding function that knows how to send to next hop
    pub forward: &'a mut dyn FnMut(&RoutingSegment, &Chdr, &Ahdr, &mut [u8]) -> Result<()>,
}

pub fn process_data_forward(_ctx: &mut NodeCtx, _chdr: &mut Chdr, _ahdr: &mut Ahdr, _payload: &mut [u8]) -> Result<()> {
    // TODO: PROC_AHDR + REMOVE_LAYER + forward
    Err(Error::NotImplemented)
}

pub fn process_data_backward(_ctx: &mut NodeCtx, _chdr: &mut Chdr, _ahdr: &mut Ahdr, _payload: &mut [u8]) -> Result<()> {
    // TODO: PROC_AHDR + ADD_LAYER + forward
    Err(Error::NotImplemented)
}

