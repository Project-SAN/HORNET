use crate::crypto::kdf::{hop_key, OpLabel};
use aes::Aes128;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

// PRP on 128-bit block (used for IV mutation and FS seal key-derivation)

pub fn prp_enc(key_src: &[u8], block: &mut [u8; 16]) {
    let mut k = [0u8; 16];
    hop_key(key_src, OpLabel::Prp, &mut k);
    let cipher = Aes128::new(GenericArray::from_slice(&k));
    let mut b = GenericArray::from_mut_slice(&mut block[..]);
    cipher.encrypt_block(&mut b);
}

pub fn prp_dec(key_src: &[u8], block: &mut [u8; 16]) {
    let mut k = [0u8; 16];
    hop_key(key_src, OpLabel::Prp, &mut k);
    let cipher = Aes128::new(GenericArray::from_slice(&k));
    let mut b = GenericArray::from_mut_slice(&mut block[..]);
    cipher.decrypt_block(&mut b);
}
