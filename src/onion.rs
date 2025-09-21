use crate::crypto::{prp, stream};
use crate::types::{Result, Si};

// {O', IV'} = ADD_LAYER(s, IV, O)
pub fn add_layer(s: &Si, iv: &mut [u8; 16], payload: &mut [u8]) -> Result<()> {
    stream::enc(&s.0, iv, payload);
    prp::prp_enc(&s.0, iv);
    Ok(())
}

// {O', IV'} = REMOVE_LAYER(s, IV, O)
pub fn remove_layer(s: &Si, iv: &mut [u8; 16], payload: &mut [u8]) -> Result<()> {
    stream::dec(&s.0, iv, payload);
    prp::prp_dec(&s.0, iv);
    Ok(())
}
