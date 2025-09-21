#![no_std]

extern crate alloc;

pub mod types;
pub mod time;
pub mod crypto;
pub mod fs_payload;
pub mod fs;
pub mod ahdr;
pub mod onion;
pub mod sphinx;
pub mod node;
pub mod source;
pub mod chdr;

pub use types::*;
pub use time::*;

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{RngCore, CryptoRng, Error as RandError};

    struct XorShift64(u64);
    impl RngCore for XorShift64 {
        fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) { self.try_fill_bytes(dest).unwrap() }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), RandError> {
            let mut n = 0;
            while n < dest.len() {
                let v = self.next_u64().to_le_bytes();
                let take = core::cmp::min(8, dest.len() - n);
                dest[n..n+take].copy_from_slice(&v[..take]);
                n += take;
            }
            Ok(())
        }
    }
    impl CryptoRng for XorShift64 {}

    #[test]
    fn e2e_setup_and_data_forward() {
        let mut rng = XorShift64(0xdead_beef_cafe_babe);
        let lf = 3usize; let lb = 3usize; let rmax = lf;
        let beta_len = rmax * C_BLOCK; let sp_len = rmax * C_BLOCK;

        fn gen_node() -> ([u8;32],[u8;32], Sv) {
            let mut sk = [0u8;32];
            let mut tmp = [0u8;32];
            XorShift64(0x1111_2222_3333_4444).try_fill_bytes(&mut tmp).unwrap();
            sk.copy_from_slice(&tmp);
            sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            let mut svb = [0u8;16];
            XorShift64(0x5555_6666_7777_8888).try_fill_bytes(&mut svb).unwrap();
            (sk, pk, Sv(svb))
        }
        let mut nodes_f = alloc::vec::Vec::new(); for _ in 0..lf { nodes_f.push(gen_node()); }
        let mut nodes_b = alloc::vec::Vec::new(); for _ in 0..lb { nodes_b.push(gen_node()); }

        let rs_f: alloc::vec::Vec<RoutingSegment> = (0..lf).map(|i| RoutingSegment(alloc::vec![i as u8; 8])).collect();
        let rs_b: alloc::vec::Vec<RoutingSegment> = (0..lb).map(|i| RoutingSegment(alloc::vec![0x80 | (i as u8); 8])).collect();
        let exp = Exp(1_000_000);

        let mut xS = [0u8;32]; rng.fill_bytes(&mut xS); xS[0]&=248; xS[31]&=127; xS[31]|=64;

        let pubkeys_f: alloc::vec::Vec<[u8;32]> = nodes_f.iter().map(|n| n.1).collect();
        let (mut shdr_f, mut sp_f, keys_f, _eph_pub_f) = crate::sphinx::source_create_forward(&xS, &pubkeys_f, beta_len, sp_len);

        let pubkeys_b: alloc::vec::Vec<[u8;32]> = nodes_b.iter().map(|n| n.1).collect();
        let (shdr_b, _sp_dummy, keys_b, _eph_pub_b) = crate::sphinx::source_create_forward(&xS, &pubkeys_b, beta_len, sp_len);

        let seed_f = { let mut s=[0u8;16]; rng.fill_bytes(&mut s); s };
        let mut p_f = crate::fs_payload::FsPayload::new_with_seed(rmax, &seed_f);
        let mut fses_f_vec = alloc::vec::Vec::new();
        for i in 0..lf {
            let (sk_i, _pk_i, sv_i) = nodes_f[i];
            let si = crate::sphinx::node_process_forward(&mut shdr_f, &mut sp_f, &sk_i, beta_len).expect("sphinx f");
            let fs_i = crate::fs::fs_create(&sv_i, &si, &rs_f[i], exp).expect("fs f");
            let _ = crate::fs_payload::add_fs_into_payload(&si, &fs_i, &mut p_f).expect("add fs f");
            fses_f_vec.push(fs_i);
        }
        let mut sp_b = crate::sphinx::dest_create_backward_sp(&p_f.bytes, sp_len);
        let seed_b = { let mut s=[0u8;16]; rng.fill_bytes(&mut s); s };
        let mut p_b = crate::fs_payload::FsPayload::new_with_seed(rmax, &seed_b);
        let mut fses_b_vec = alloc::vec::Vec::new();
        for j in 0..lb {
            let (sk_j, _pk_j, sv_j) = nodes_b[j];
            let sj = crate::sphinx::node_process_backward(&shdr_b, &mut sp_b, &sk_j).expect("sphinx b");
            let fs_j = crate::fs::fs_create(&sv_j, &sj, &rs_b[j], exp).expect("fs b");
            let _ = crate::fs_payload::add_fs_into_payload(&sj, &fs_j, &mut p_b).expect("add fs b");
            fses_b_vec.push(fs_j);
        }
        let _pf_bytes = crate::sphinx::source_unwrap_backward(&keys_b, &sp_b);
        // Use collected FSes directly for AHDR construction in this mock
        let fses_f = fses_f_vec;
        let fses_b = fses_b_vec;

        let mut rng2 = XorShift64(0x9999_aaaa_bbbb_cccc);
        let ahdr_f = crate::ahdr::create_ahdr(&keys_f, &fses_f, rmax, &mut rng2).expect("ahdr f");
        let _ahdr_b = crate::ahdr::create_ahdr(&keys_b, &fses_b, rmax, &mut rng2).expect("ahdr b");

        let mut payload = alloc::vec![0u8; 64]; for i in 0..payload.len() { payload[i] = (i as u8) ^ 0x5a; }
        let mut iv0 = [0u8;16]; rng.fill_bytes(&mut iv0);
        let orig = payload.clone();
        crate::source::encrypt_forward_payload(&keys_f, &mut iv0, &mut payload).expect("enc f");

        let mut iv = iv0;
        for i in 0..lf {
            crate::onion::remove_layer(&keys_f[i], &mut iv, &mut payload).expect("remove");
        }
        assert_eq!(&payload, &orig);
    }
}
