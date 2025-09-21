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
    #[cfg(feature = "strict_sphinx")]
    use curve25519_dalek::scalar::Scalar;

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
        let (mut shdr_b, _sp_dummy, keys_b, eph_pub_b) = crate::sphinx::source_create_forward(&xS, &pubkeys_b, beta_len, sp_len);
        // For backward, keep y as eph_pub so nodes derive the same shared as the source
        shdr_b.y = eph_pub_b;

        let seed_f = { let mut s=[0u8;16]; rng.fill_bytes(&mut s); s };
        let mut p_f = crate::fs_payload::FsPayload::new_with_seed(rmax, &seed_f);
        let mut fses_f_vec = alloc::vec::Vec::new();
        for i in 0..lf {
            let (sk_i, _pk_i, sv_i) = nodes_f[i];
            let _si_node = crate::sphinx::node_process_forward(&mut shdr_f, &mut sp_f, &sk_i, beta_len).expect("sphinx f");
            let fs_i = crate::fs::fs_create(&sv_i, &keys_f[i], &rs_f[i], exp).expect("fs f");
            let _ = crate::fs_payload::add_fs_into_payload(&keys_f[i], &fs_i, &mut p_f).expect("add fs f");
            fses_f_vec.push(fs_i);
        }
        let mut sp_b = crate::sphinx::dest_create_backward_sp(&p_f.bytes, sp_len);
        let seed_b = { let mut s=[0u8;16]; rng.fill_bytes(&mut s); s };
        let mut p_b = crate::fs_payload::FsPayload::new_with_seed(rmax, &seed_b);
        let mut fses_b_vec = alloc::vec::Vec::new();
        for j in 0..lb {
            let (sk_j, _pk_j, sv_j) = nodes_b[j];
            let _sj_node = crate::sphinx::node_process_backward(&shdr_b, &mut sp_b, &sk_j).expect("sphinx b");
            let fs_j = crate::fs::fs_create(&sv_j, &keys_b[j], &rs_b[j], exp).expect("fs b");
            let _ = crate::fs_payload::add_fs_into_payload(&keys_b[j], &fs_j, &mut p_b).expect("add fs b");
            fses_b_vec.push(fs_j);
        }
        let _pf_bytes = crate::sphinx::source_unwrap_backward(&keys_b, &sp_b);
        // Unwrap SPb to get Pf and retrieve FSes per Alg.2
        // Unwrap SPb to get Pf and retrieve FSes per Alg.2
        let pf_bytes = crate::sphinx::source_unwrap_backward(&keys_b, &sp_b);
        let pf_recv = crate::fs_payload::FsPayload { bytes: pf_bytes, rmax };
        let fses_f = crate::fs_payload::retrieve_fses(&keys_f, &seed_f, &pf_recv).expect("ret fs f");
        let fses_b = crate::fs_payload::retrieve_fses(&keys_b, &seed_b, &p_b).expect("ret fs b");

        let mut rng2 = XorShift64(0x9999_aaaa_bbbb_cccc);
        let ahdr_f = crate::ahdr::create_ahdr(&keys_f, &fses_f, rmax, &mut rng2).expect("ahdr f");
        let _ahdr_b = crate::ahdr::create_ahdr(&keys_b, &fses_b, rmax, &mut rng2).expect("ahdr b");

        let mut payload = alloc::vec![0u8; 64]; for i in 0..payload.len() { payload[i] = (i as u8) ^ 0x5a; }
        let mut iv0 = [0u8;16]; rng.fill_bytes(&mut iv0);
        let orig = payload.clone();
        crate::source::encrypt_forward_payload(&keys_f, &mut iv0, &mut payload).expect("enc f");

        // Forward process with AHDR at each hop
        let mut iv = iv0;
        let mut ah = ahdr_f;
        for i in 0..lf {
            let pr = crate::ahdr::proc_ahdr(&nodes_f[i].2, &ah, Exp(0)).expect("proc ahdr");
            crate::onion::remove_layer(&pr.s, &mut iv, &mut payload).expect("remove");
            ah = pr.ahdr_next;
        }
        assert_eq!(&payload, &orig);
    }

    #[test]
    fn fs_retrieve_padding_r_gt_l() {
        let mut rng = XorShift64(0x1234_5678_9abc_def0);
        let rmax = 4usize; let lf = 3usize; let lb = 3usize;
        let beta_len = rmax * C_BLOCK; let sp_len = rmax * C_BLOCK;

        fn gen_node(seed: u64) -> ([u8;32],[u8;32], Sv) {
            let mut sk = [0u8;32];
            let mut tmp = [0u8;32];
            XorShift64(seed).try_fill_bytes(&mut tmp).unwrap();
            sk.copy_from_slice(&tmp); sk[0]&=248; sk[31]&=127; sk[31]|=64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            let mut svb = [0u8;16]; XorShift64(seed^0x9e37_79b9).try_fill_bytes(&mut svb).unwrap();
            (sk, pk, Sv(svb))
        }
        let mut nodes_f = alloc::vec::Vec::new(); for i in 0..lf { nodes_f.push(gen_node(0x1000 + i as u64)); }
        let mut nodes_b = alloc::vec::Vec::new(); for i in 0..lb { nodes_b.push(gen_node(0x2000 + i as u64)); }

        let rs_f: alloc::vec::Vec<RoutingSegment> = (0..lf).map(|i| RoutingSegment(alloc::vec![i as u8; 8])).collect();
        let rs_b: alloc::vec::Vec<RoutingSegment> = (0..lb).map(|i| RoutingSegment(alloc::vec![0x80 | (i as u8); 8])).collect();
        let exp = Exp(2_000_000);

        let mut xS = [0u8;32]; rng.fill_bytes(&mut xS); xS[0]&=248; xS[31]&=127; xS[31]|=64;
        let pubkeys_f: alloc::vec::Vec<[u8;32]> = nodes_f.iter().map(|n| n.1).collect();
        let (mut shdr_f, mut sp_f, keys_f, _eph_pub_f) = crate::sphinx::source_create_forward(&xS, &pubkeys_f, beta_len, sp_len);
        let pubkeys_b: alloc::vec::Vec<[u8;32]> = nodes_b.iter().map(|n| n.1).collect();
        let (mut shdr_b, _sp_dummy, keys_b, eph_pub_b) = crate::sphinx::source_create_forward(&xS, &pubkeys_b, beta_len, sp_len);
        shdr_b.y = eph_pub_b;

        let seed_f = { let mut s=[0u8;16]; rng.fill_bytes(&mut s); s };
        let mut p_f = crate::fs_payload::FsPayload::new_with_seed(rmax, &seed_f);
        for i in 0..lf {
            let (sk_i, _pk_i, sv_i) = nodes_f[i];
            let _ = crate::sphinx::node_process_forward(&mut shdr_f, &mut sp_f, &sk_i, beta_len).expect("sphinx f");
            let fs_i = crate::fs::fs_create(&sv_i, &keys_f[i], &rs_f[i], exp).expect("fs f");
            let _ = crate::fs_payload::add_fs_into_payload(&keys_f[i], &fs_i, &mut p_f).expect("add fs f");
        }
        let mut sp_b = crate::sphinx::dest_create_backward_sp(&p_f.bytes, sp_len);
        let seed_b = { let mut s=[0u8;16]; rng.fill_bytes(&mut s); s };
        let mut p_b = crate::fs_payload::FsPayload::new_with_seed(rmax, &seed_b);
        for j in 0..lb {
            let (sk_j, _pk_j, sv_j) = nodes_b[j];
            let _ = crate::sphinx::node_process_backward(&shdr_b, &mut sp_b, &sk_j).expect("sphinx b");
            let fs_j = crate::fs::fs_create(&sv_j, &keys_b[j], &rs_b[j], exp).expect("fs b");
            let _ = crate::fs_payload::add_fs_into_payload(&keys_b[j], &fs_j, &mut p_b).expect("add fs b");
        }
        let pf_bytes = crate::sphinx::source_unwrap_backward(&keys_b, &sp_b);
        let pf_recv = crate::fs_payload::FsPayload { bytes: pf_bytes, rmax };
        let _fses_f = crate::fs_payload::retrieve_fses(&keys_f, &seed_f, &pf_recv).expect("ret fs f (r>l)");
        let _fses_b = crate::fs_payload::retrieve_fses(&keys_b, &seed_b, &p_b).expect("ret fs b (r>l)");
    }

    #[test]
    fn e2e_backward_ahdr_and_data() {
        let mut rng = XorShift64(0xa1a2_a3a4_a5a6_a7a8);
        let lf = 3usize; let lb = 3usize; let rmax = lb;
        let beta_len = rmax * C_BLOCK; let sp_len = rmax * C_BLOCK;

        fn gen_node(seed: u64) -> ([u8;32],[u8;32], Sv) {
            let mut sk = [0u8;32]; let mut tmp = [0u8;32];
            XorShift64(seed).try_fill_bytes(&mut tmp).unwrap();
            sk.copy_from_slice(&tmp); sk[0]&=248; sk[31]&=127; sk[31]|=64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            let mut svb = [0u8;16]; XorShift64(seed ^ 0x5555_aaaa_dead_beef).try_fill_bytes(&mut svb).unwrap();
            (sk, pk, Sv(svb))
        }
        let mut nodes_f = alloc::vec::Vec::new(); for i in 0..lf { nodes_f.push(gen_node(0x3000 + i as u64)); }
        let mut nodes_b = alloc::vec::Vec::new(); for i in 0..lb { nodes_b.push(gen_node(0x4000 + i as u64)); }
        let rs_f: alloc::vec::Vec<RoutingSegment> = (0..lf).map(|i| RoutingSegment(alloc::vec![i as u8; 8])).collect();
        let rs_b: alloc::vec::Vec<RoutingSegment> = (0..lb).map(|i| RoutingSegment(alloc::vec![0x80 | (i as u8); 8])).collect();
        let exp = Exp(3_000_000);

        // Source ephemeral secret
        let mut xS = [0u8;32]; rng.fill_bytes(&mut xS); xS[0]&=248; xS[31]&=127; xS[31]|=64;
        // Forward build to collect FS forward (not used directly here)
        let pubkeys_f: alloc::vec::Vec<[u8;32]> = nodes_f.iter().map(|n| n.1).collect();
        let (mut shdr_f, mut sp_f, keys_f, _eph_pub_f) = crate::sphinx::source_create_forward(&xS, &pubkeys_f, beta_len, sp_len);
        let seed_f = { let mut s=[0u8;16]; rng.fill_bytes(&mut s); s };
        let mut p_f = crate::fs_payload::FsPayload::new_with_seed(rmax, &seed_f);
        for i in 0..lf {
            let (sk_i, _pk_i, sv_i) = nodes_f[i];
            let _ = crate::sphinx::node_process_forward(&mut shdr_f, &mut sp_f, &sk_i, beta_len).expect("sphinx f");
            let fs_i = crate::fs::fs_create(&sv_i, &keys_f[i], &rs_f[i], exp).expect("fs f");
            let _ = crate::fs_payload::add_fs_into_payload(&keys_f[i], &fs_i, &mut p_f).expect("add fs f");
        }
        // Backward build
        let pubkeys_b: alloc::vec::Vec<[u8;32]> = nodes_b.iter().map(|n| n.1).collect();
        let (mut shdr_b, _sp_dummy, keys_b, eph_pub_b) = crate::sphinx::source_create_forward(&xS, &pubkeys_b, beta_len, sp_len);
        shdr_b.y = eph_pub_b;
        let seed_b = { let mut s=[0u8;16]; rng.fill_bytes(&mut s); s };
        let mut p_b = crate::fs_payload::FsPayload::new_with_seed(rmax, &seed_b);
        for j in 0..lb {
            let (sk_j, _pk_j, sv_j) = nodes_b[j];
            let _ = crate::sphinx::node_process_backward(&shdr_b, &mut crate::sphinx::dest_create_backward_sp(&p_f.bytes, sp_len), &sk_j).expect("sphinx b");
            let fs_j = crate::fs::fs_create(&sv_j, &keys_b[j], &rs_b[j], exp).expect("fs b");
            let _ = crate::fs_payload::add_fs_into_payload(&keys_b[j], &fs_j, &mut p_b).expect("add fs b");
        }
        // Retrieve FS for backward path
        let fses_b = crate::fs_payload::retrieve_fses(&keys_b, &seed_b, &p_b).expect("ret fs b");
        // Build backward AHDR with reversed order (first hop from destination is last in keys_b)
        let mut rng2 = XorShift64(0x7777_8888_9999_aaaa);
        let mut keys_b_rev = keys_b.clone(); keys_b_rev.reverse();
        let mut fses_b_rev = fses_b.clone(); fses_b_rev.reverse();
        let mut ahdr_b = crate::ahdr::create_ahdr(&keys_b_rev, &fses_b_rev, rmax, &mut rng2).expect("ahdr b");

        // Destination encrypts payload and each node adds a layer while processing AHDR
        let mut payload = alloc::vec![0u8; 96]; for i in 0..payload.len() { payload[i] = (0x30 + (i as u8)) ^ 0x33; }
        let mut iv = { let mut v=[0u8;16]; rng.fill_bytes(&mut v); v };
        // Destination adds first layer using last key (keys_b_rev[0]) via proc_ahdr at node nodes_b[lb-1]
        let mut ah = ahdr_b;
        for hop in (0..lb).rev() { // nodes from far (lb-1) to near (0)
            let pr = crate::ahdr::proc_ahdr(&nodes_b[hop].2, &ah, Exp(0)).expect("proc ahdr b");
            crate::onion::add_layer(&pr.s, &mut iv, &mut payload).expect("add layer b");
            ah = pr.ahdr_next;
        }
        // Decrypt by replaying layers removal in reverse add order (keys_b_rev) with matching IV evolution
        let mut iv3 = iv; let mut data2 = payload.clone();
        for k in (0..lb).rev() { crate::onion::remove_layer(&keys_b_rev[k], &mut iv3, &mut data2).expect("rem b"); }
        // The resulting plaintext must match the original destination payload
        let mut orig = alloc::vec![0u8; 96]; for i in 0..orig.len() { orig[i] = (0x30 + (i as u8)) ^ 0x33; }
        assert_eq!(data2, orig);
    }

    #[cfg(feature = "strict_sphinx")]
    #[test]
    fn strict_sphinx_header_chain_and_tamper() {
        let mut rng = XorShift64(0xabc1_def2_3456_7890);
        let r = 3usize; let beta_len = r * C_BLOCK;
        // Build node keys
        let mut nodes = alloc::vec::Vec::new();
        for i in 0..r {
            let mut sk = [0u8;32]; rng.fill_bytes(&mut sk); sk[0]&=248; sk[31]&=127; sk[31]|=64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            nodes.push((sk, pk));
        }
        // Source ephemeral
        let mut xS = [0u8;32]; rng.fill_bytes(&mut xS); xS[0]&=248; xS[31]&=127; xS[31]|=64;
        let pubs: alloc::vec::Vec<[u8;32]> = nodes.iter().map(|n| n.1).collect();
        let (mut h, _sis, _eph_pub) = crate::sphinx::strict::source_create_forward_strict(&xS, &pubs, beta_len);
        // Process across hops
        for i in 0..r { let _ = crate::sphinx::strict::node_process_forward_strict(&mut h, &nodes[i].0).expect("strict hop"); }
        // Tamper test: rebuild header and flip one bit in beta, first hop should reject
        let (mut h2, _sis2, _eph_pub2) = crate::sphinx::strict::source_create_forward_strict(&xS, &pubs, beta_len);
        h2.beta[0] ^= 1;
        let res = crate::sphinx::strict::node_process_forward_strict(&mut h2, &nodes[0].0);
        assert!(matches!(res, Err(Error::InvalidMac)));
    }

    #[cfg(feature = "strict_sphinx")]
    #[test]
    fn strict_sphinx_step_by_step_states() {
        let mut rng = XorShift64(0x5555_2222_9999_dddd);
        let r = 3usize; let beta_len = r * C_BLOCK;
        // Build node keys
        let mut nodes = alloc::vec::Vec::new();
        for i in 0..r {
            let mut sk = [0u8;32]; rng.fill_bytes(&mut sk); sk[0]&=248; sk[31]&=127; sk[31]|=64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            nodes.push((sk, pk));
        }
        let mut xS = [0u8;32]; rng.fill_bytes(&mut xS); xS[0]&=248; xS[31]&=127; xS[31]|=64;
        let pubs: alloc::vec::Vec<[u8;32]> = nodes.iter().map(|n| n.1).collect();
        let (mut h, _sis, _eph_pub, snaps) = crate::sphinx::strict::source_create_forward_strict_trace(&xS, &pubs, beta_len);
        // Node 0 sees snaps[0]
        assert_eq!(h.beta, snaps[0]);
        // Process hop 0
        let _ = crate::sphinx::strict::node_process_forward_strict(&mut h, &nodes[0].0).expect("hop0");
        // After unmask, header beta should match snaps[1]
        assert_eq!(h.beta, snaps[1]);
        // Process hop 1
        let _ = crate::sphinx::strict::node_process_forward_strict(&mut h, &nodes[1].0).expect("hop1");
        // After unmask, header beta should match snaps[2]
        assert_eq!(h.beta, snaps[2]);
    }

    #[test]
    fn ahdr_expiry_check() {
        // Single-hop AHDR with a fixed EXP; proc_ahdr should pass when now < EXP and fail when now >= EXP.
        let mut rng = XorShift64(0x0f0e_0d0c_0b0a_0908);
        let rmax = 1usize;
        // Generate one node context
        let mut svb = [0u8;16]; rng.fill_bytes(&mut svb);
        let sv = Sv(svb);
        let mut key = [0u8;16]; rng.fill_bytes(&mut key);
        let si = Si(key);
        let rseg = RoutingSegment(alloc::vec![0u8; 8]);
        let exp = Exp(1_234_567);
        let fs = crate::fs::fs_create(&sv, &si, &rseg, exp).expect("fs");
        let mut rng2 = XorShift64(0x0102_0304_0506_0708);
        let ahdr = crate::ahdr::create_ahdr(&[si], &[fs], rmax, &mut rng2).expect("ahdr");
        // now < EXP → OK
        let pr = crate::ahdr::proc_ahdr(&sv, &ahdr, Exp(exp.0 - 1)).expect("proc ok before exp");
        // now >= EXP → Expired
        let err = crate::ahdr::proc_ahdr(&sv, &ahdr, Exp(exp.0)).err().expect("must error at exp");
        assert!(matches!(err, Error::Expired));
    }
}
