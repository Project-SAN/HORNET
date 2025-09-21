use crate::types::{Ahdr, Chdr, Exp, Result, RoutingSegment, Sv};
use crate::ahdr::proc_ahdr;
use crate::onion;

pub struct NodeCtx<'a> {
    pub sv: Sv,
    pub now: &'a dyn crate::time::TimeProvider,
    // User supplies a forwarding function that knows how to send to next hop
    pub forward: &'a mut dyn FnMut(&RoutingSegment, &Chdr, &Ahdr, &mut [u8]) -> Result<()>,
}

pub fn process_data_forward(ctx: &mut NodeCtx, chdr: &mut Chdr, ahdr: &mut Ahdr, payload: &mut [u8]) -> Result<()> {
    let now = Exp(ctx.now.now_coarse());
    let res = proc_ahdr(&ctx.sv, ahdr, now)?;
    // Remove one onion layer and mutate IV in CHDR.specific
    let mut iv = chdr.specific;
    onion::remove_layer(&res.s, &mut iv, payload)?;
    chdr.specific = iv;
    // Forward to next hop using routing segment
    (ctx.forward)(&res.r, chdr, &res.ahdr_next, payload)
}

pub fn process_data_backward(ctx: &mut NodeCtx, chdr: &mut Chdr, ahdr: &mut Ahdr, payload: &mut [u8]) -> Result<()> {
    let now = Exp(ctx.now.now_coarse());
    let res = proc_ahdr(&ctx.sv, ahdr, now)?;
    // Add one onion layer and mutate IV in CHDR.specific
    let mut iv = chdr.specific;
    onion::add_layer(&res.s, &mut iv, payload)?;
    chdr.specific = iv;
    (ctx.forward)(&res.r, chdr, &res.ahdr_next, payload)
}
