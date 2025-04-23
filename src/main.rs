#![deny(warnings)]

#[cfg(test)]
extern crate quickcheck_macros;

// use blake2::Blake2bMac;
use clap::{StructOpt, ValueEnum};
use clap_complete::{generate, generate_to, Shell};
use conv::ApproxFrom;
use core::cmp::{max, min};
// use digest::{FixedOutput, Mac};
use generic_array::{ArrayLength, GenericArray};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::convert::TryInto;
use std::fmt;
use std::fs::File;
use std::io::ErrorKind;
use std::io::Seek;
use std::io::Write;
use std::path::PathBuf;
use subtle::ConstantTimeEq;
use typenum::{
    consts::{U32, U64},
    IsLessOrEqual, LeEq, NonZero,
};

enum ScrombleError {
    TooShort,
    BadHmac,
    FileChanged,
    Overflow,
}

impl fmt::Display for ScrombleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScrombleError::TooShort => {
                write!(f, "File is too short to be a valid scromble file")
            }
            ScrombleError::BadHmac => {
                write!(f, "Ciphertext has an invalid HMAC")
            }
            ScrombleError::FileChanged => {
                write!(f, "File contents changed while decrypting")
            }
            ScrombleError::Overflow => {
                write!(f, "An integer overflow occurred")
            }
        }
    }
}

impl fmt::Debug for ScrombleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (&self as &dyn fmt::Display).fmt(f)
    }
}

impl std::error::Error for ScrombleError {}

///// begin unfortunate vendored XChaCha20 impl //////

mod chacha {
    use super::*;

    use zeroize::DefaultIsZeroes; //,Zeroize};//,ZeroizeOnDrop};

    #[derive(Default, Clone, Copy)]
    struct ChaChaKey(pub [u32; 8]);
    impl DefaultIsZeroes for ChaChaKey {}

    #[derive(Default, Clone, Copy)]
    struct ChaChaState(pub [u32; 16]);
    impl DefaultIsZeroes for ChaChaState {}

    #[derive(Default, Clone, Copy)]
    struct ChaChaNonce(pub [u32; 2]);
    impl DefaultIsZeroes for ChaChaNonce {}

    #[derive(Default, Clone, Copy)]
    struct HChaChaNonce(pub [u32; 4]);
    impl zeroize::DefaultIsZeroes for HChaChaNonce {}

    /// State initialization constant ("expand 32-byte k")

    const CONSTANTS: [u32; 4] =
        [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

    /// The ChaCha20 quarter round function
    #[allow(dead_code)]
    #[inline(always)]
    fn quarter_round(
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        state: &mut ChaChaState,
    ) {
        state.0[a] = state.0[a].wrapping_add(state.0[b]);
        state.0[d] ^= state.0[a];
        state.0[d] = state.0[d].rotate_left(16);

        state.0[c] = state.0[c].wrapping_add(state.0[d]);
        state.0[b] ^= state.0[c];
        state.0[b] = state.0[b].rotate_left(12);

        state.0[a] = state.0[a].wrapping_add(state.0[b]);
        state.0[d] ^= state.0[a];
        state.0[d] = state.0[d].rotate_left(8);

        state.0[c] = state.0[c].wrapping_add(state.0[d]);
        state.0[b] ^= state.0[c];
        state.0[b] = state.0[b].rotate_left(7);
    }

    /// The ChaCha20 quarter round function
    #[inline(always)]
    fn quarter_rounds(
        a: [&mut u32; 4],
        b: [&mut u32; 4],
        c: [&mut u32; 4],
        d: [&mut u32; 4],
    ) {
        for i in 0..4 {
            *a[i] = a[i].wrapping_add(*b[i]);
            *d[i] ^= *a[i];
            *d[i] = d[i].rotate_left(16);

            *c[i] = c[i].wrapping_add(*d[i]);
            *b[i] ^= *c[i];
            *b[i] = b[i].rotate_left(12);

            *a[i] = a[i].wrapping_add(*b[i]);
            *d[i] ^= *a[i];
            *d[i] = d[i].rotate_left(8);

            *c[i] = c[i].wrapping_add(*d[i]);
            *b[i] ^= *c[i];
            *b[i] = b[i].rotate_left(7);
        }
    }

    #[inline(always)]
    fn run_rounds_inner(double_rounds: usize, res: &mut ChaChaState) {
        for _ in 0..double_rounds {
            let [x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11, x12, x13, x14, x15] =
                &mut res.0;

            // column rounds
            quarter_rounds(
                [x00, x01, x02, x03],
                [x04, x05, x06, x07],
                [x08, x09, x10, x11],
                [x12, x13, x14, x15],
            );

            // diagonal rounds
            quarter_rounds(
                [x00, x01, x02, x03],
                [x05, x06, x07, x04],
                [x10, x11, x08, x09],
                [x15, x12, x13, x14],
            );
        }
    }

    #[inline(always)]
    fn run_rounds(
        double_rounds: usize,
        state: &ChaChaState,
    ) -> ChaChaState {
        let mut res = *state;

        run_rounds_inner(double_rounds, &mut res);

        for (s1, s0) in res.0.iter_mut().zip(state.0.iter()) {
            *s1 = s1.wrapping_add(*s0);
        }
        res
    }

    /// The HChaCha function: adapts the ChaCha core function in the same
    /// manner that HSalsa adapts the Salsa function.
    ///
    /// HChaCha takes 384 bits of input:
    ///
    /// - Key: `u32` x 8
    /// - Nonce: `u32` x 4
    ///
    /// It produces 256-bits of output suitable for use as a ChaCha key
    ///
    /// For more information on HSalsa on which HChaCha is based, see:
    ///
    /// <http://cr.yp.to/snuffle/xsalsa-20110204.pdf>
    fn hchacha(key: ChaChaKey, nonce: HChaChaNonce) -> ChaChaKey {
        let mut state = ChaChaState::default();
        state.0[..4].copy_from_slice(&CONSTANTS);

        state.0[4..12].copy_from_slice(&key.0[..]);
        state.0[12..16].copy_from_slice(&nonce.0[..]);

        run_rounds_inner(10, &mut state);

        let mut output = ChaChaKey::default();

        output.0[0..4].copy_from_slice(&state.0[..4]);
        output.0[4..8].copy_from_slice(&state.0[12..16]);

        output
    }

    #[inline(always)]
    fn chacha20_apply_block(
        key: &ChaChaKey,
        nonce: &ChaChaNonce,
        block_ix: u64,
        pt: &mut [u8; 64],
    ) {
        let mut state = ChaChaState::default();
        state.0[..4].copy_from_slice(&CONSTANTS);

        state.0[4..12].copy_from_slice(&key.0[..]);

        state.0[12] = (block_ix & 0xffff_ffff) as u32;
        state.0[13] = ((block_ix >> 32) & 0xffff_ffff) as u32;
        state.0[14] = nonce.0[0];
        state.0[15] = nonce.0[1];

        state = run_rounds(10, &state);

        for i in 0..state.0.len() {
            let w = state.0[i];
            let mask = w.to_le_bytes();
            for j in 0..mask.len() {
                pt[4 * i + j] ^= mask[j];
            }
        }
    }

    pub struct CipherState {
        key: SecretBox<ChaChaKey>,
        nonce: SecretBox<ChaChaNonce>,
        block_ix: u64,
        offset: u8,
    }

    impl CipherState {
        pub fn new(key_bytes: &[u8; 32], nonce_bytes: &[u8; 24]) -> Self {
            let nonce = SecretBox::<ChaChaNonce>::init_with_mut(|n| {
                n.0[0] = u32::from_le_bytes(
                    nonce_bytes[16..20].try_into().unwrap(),
                );
                n.0[1] = u32::from_le_bytes(
                    nonce_bytes[20..24].try_into().unwrap(),
                );
            });
            let key = SecretBox::<ChaChaKey>::init_with_mut(|k| {
                for (k, val) in k.0.iter_mut().zip(
                    key_bytes
                        .chunks_exact(4)
                        .map(|b| b.try_into().unwrap())
                        .map(u32::from_le_bytes),
                ) {
                    *k = val;
                }

                let nonce: HChaChaNonce = HChaChaNonce([
                    u32::from_le_bytes(
                        nonce_bytes[0..4].try_into().unwrap(),
                    ),
                    u32::from_le_bytes(
                        nonce_bytes[4..8].try_into().unwrap(),
                    ),
                    u32::from_le_bytes(
                        nonce_bytes[8..12].try_into().unwrap(),
                    ),
                    u32::from_le_bytes(
                        nonce_bytes[12..16].try_into().unwrap(),
                    ),
                ]);

                *k = hchacha(*k, nonce);
            });

            Self {
                key,
                nonce,
                block_ix: 0,
                offset: 0,
            }
        }

        pub fn try_seek<U: Into<u128>>(
            &mut self,
            pos: U,
        ) -> Result<(), ScrombleError> {
            let pos: u128 = pos.into();
            let offset = (pos & 0x3F) as u8;
            let block_ix: u64 = (pos >> 6)
                .try_into()
                .map_err(|_| ScrombleError::Overflow)?;
            self.block_ix = block_ix;
            self.offset = offset;
            Ok(())
        }

        #[allow(unused)]
        pub fn try_current_pos<U: std::convert::TryFrom<u128>>(
            &self,
        ) -> Result<U, ScrombleError> {
            U::try_from(
                (self.block_ix as u128) * 64 + (self.offset as u128),
            )
            .map_err(|_| ScrombleError::Overflow)
        }

        pub fn try_apply_keystream(
            &mut self,
            mut buffer: &mut [u8],
        ) -> Result<(), ScrombleError> {
            let final_pos: u128 = ((self.block_ix as u128) * 64
                + (self.offset as u128))
                .saturating_add(buffer.len() as u128);
            if final_pos > (1u128 << (64 + 6)) {
                return Err(ScrombleError::Overflow);
            }

            if buffer.len() == 0 {
                return Ok(());
            }

            let mut offset = self.offset;
            let mut block_ix = self.block_ix;

            let key = self.key.expose_secret();
            let nonce = self.nonce.expose_secret();

            if offset > 0 {
                let num_bytes = min(buffer.len(), 64 - (offset as usize));
                let mut block = [0u8; 64];
                let off = offset as usize;
                block[off..off + num_bytes]
                    .copy_from_slice(&buffer[..num_bytes]);

                chacha20_apply_block(key, nonce, block_ix, &mut block);

                buffer[..num_bytes]
                    .copy_from_slice(&block[off..off + num_bytes]);

                offset += num_bytes as u8;
                buffer = &mut buffer[num_bytes..];
            }

            if offset == 64 {
                match block_ix.checked_add(1) {
                    Some(new_ix) => {
                        offset = 0;
                        block_ix = new_ix;
                    }
                    None => {
                        assert!(buffer.len() == 0);
                    }
                }
            }

            const N_CHUNKS: usize = 4;
            while buffer.len() >= N_CHUNKS * 64 {
                let mut ixs = [0u64; N_CHUNKS];
                for i in 0..N_CHUNKS {
                    ixs[i] = block_ix
                        .checked_add(i as u64)
                        .ok_or(ScrombleError::Overflow)?;
                }

                let mut block = [[0u8; 64]; N_CHUNKS];
                for i in 0..N_CHUNKS {
                    block[i][..]
                        .copy_from_slice(&buffer[i * 64..(i + 1) * 64]);
                }

                for i in 0..N_CHUNKS {
                    chacha20_apply_block(
                        key,
                        nonce,
                        ixs[i],
                        &mut block[i],
                    );
                }

                for i in 0..N_CHUNKS {
                    buffer[i * 64..(i + 1) * 64]
                        .copy_from_slice(&block[i][..]);
                }

                match block_ix.checked_add(N_CHUNKS as u64) {
                    Some(ix) => {
                        block_ix = ix;
                    }
                    None => {
                        block_ix = u64::MAX;
                        offset = 64;
                    }
                }

                buffer = &mut buffer[N_CHUNKS * 64..];
            }

            while buffer.len() >= 64 {
                let mut block = [0u8; 64];
                block[..].copy_from_slice(&buffer[..64]);

                chacha20_apply_block(key, nonce, block_ix, &mut block);

                buffer[..64].copy_from_slice(&block[..]);

                match block_ix.checked_add(1) {
                    Some(ix) => {
                        block_ix = ix;
                    }
                    None => {
                        block_ix = u64::MAX;
                        offset = 64;
                    }
                }

                buffer = &mut buffer[64..];
            }

            if buffer.len() > 0 {
                assert!(buffer.len() <= 63);
                assert_eq!(offset, 0);

                let mut block = [0u8; 64];
                block[..buffer.len()].copy_from_slice(&buffer[..]);

                chacha20_apply_block(key, nonce, block_ix, &mut block);

                let buflen = buffer.len();
                buffer[..].copy_from_slice(&block[..buflen]);

                offset = buffer.len() as u8;
            }

            self.block_ix = block_ix;
            self.offset = offset;

            return Ok(());
        }
    }

    #[cfg(test)]
    mod chacha20_tests {
        use super::*;

        #[test]
        fn chacha_known_answer() {
            let mut state = CipherState {
                key: SecretBox::new(Box::new(ChaChaKey::default())),
                nonce: SecretBox::new(Box::new(ChaChaNonce::default())),
                block_ix: 0,
                offset: 0,
            };

            let mut expected_answer = [
                0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40,
                0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28, 0xbd, 0xd2,
                0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef,
                0xcc, 0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c,
                0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8,
                0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18,
                0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65,
                0x86,
            ];

            state.try_apply_keystream(&mut expected_answer[..]).unwrap();
            let mut i = 0;
            for x in expected_answer {
                assert_eq!(x, 0, "{}", i);
                i += 1;
            }
        }

        #[test]
        fn xchacha_known_answer() {
            let key = [
                0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
                0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91,
                0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
                0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
            ];
            let nonce = [
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
                0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51,
                0x52, 0x53, 0x54, 0x55, 0x56, 0x58,
            ];
            let mut state = CipherState::new(&key, &nonce);

            let mut expected_answers = [
                vec![
                    0x29, 0x62, 0x4b, 0x4b, 0x1b, 0x14, 0x0a, 0xce, 0x53,
                    0x74, 0x0e, 0x40, 0x5b, 0x21, 0x68,
                ],
                vec![0x54, 0x0f],
            ];

            state.try_seek(64u64).unwrap();
            let mut i = 0;
            for expected_answer in expected_answers.iter_mut() {
                state
                    .try_apply_keystream(&mut expected_answer[..])
                    .unwrap();
                for x in expected_answer {
                    assert_eq!(*x, 0, "{}", i);
                    i += 1;
                }
            }
        }

        mod overflow {
            use super::*;

            const OFFSET_256GB: u64 = 256u64 << 30;
            const OFFSET_256PB: u64 = 256u64 << 50;
            const OFFSET_1ZB: u128 = (64u128) << 64;

            #[test]
            fn xchacha_256gb() {
                let mut cipher = CipherState::new(
                    &Default::default(),
                    &Default::default(),
                );
                cipher
                    .try_seek(OFFSET_256GB - 1)
                    .expect("Couldn't seek to nearly 256GB");
                let mut data = [0u8; 1];
                cipher
                    .try_apply_keystream(&mut data)
                    .expect("Couldn't encrypt the last byte of 256GB");
                assert_eq!(
                    cipher.try_current_pos::<u64>().unwrap(),
                    OFFSET_256GB
                );
                let mut data = [0u8; 1];
                cipher.try_apply_keystream(&mut data).expect(
                    "Couldn't encrypt past the last byte of 256GB",
                );
            }

            #[test]
            fn xchacha_upper_limit() {
                let mut cipher = CipherState::new(
                    &Default::default(),
                    &Default::default(),
                );
                cipher
                    .try_seek(OFFSET_1ZB - 1)
                    .expect("Couldn't seek to nearly 1 zebibyte");
                let mut data = [0u8; 1];
                cipher.try_apply_keystream(&mut data).expect(
                    "Couldn't encrypt the last byte of 1 zebibyte",
                );
                let mut data = [0u8; 1];
                cipher
                    .try_apply_keystream(&mut data)
                    .expect_err("Could encrypt past 1 zebibyte");
            }

            #[test]
            fn xchacha_has_a_big_counter() {
                let mut cipher = CipherState::new(
                    &Default::default(),
                    &Default::default(),
                );
                cipher
                    .try_seek(OFFSET_256PB)
                    .expect("Could seek to 256PB");
                let mut data = [0u8; 1];
                cipher
                    .try_apply_keystream(&mut data)
                    .expect("Couldn't encrypt the next byte after 256PB");
            }
        }
    }

    #[cfg(test)]
    mod hchacha20_tests {
        use super::*;

        //
        // Test vectors from:
        // https://tools.ietf.org/id/draft-arciszewski-xchacha-03.html#rfc.section.2.2.1
        //

        const KEY: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];

        const INPUT: [u8; 16] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00,
            0x00, 0x00, 0x31, 0x41, 0x59, 0x27,
        ];

        const OUTPUT: [u8; 32] = [
            0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0xe,
            0x42, 0x50, 0x8a, 0x87, 0x7d, 0x73, 0xa0, 0xf9, 0xe4, 0xd5,
            0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13, 0x26, 0xd3,
            0xec, 0xdc,
        ];

        #[test]
        fn test_vector() {
            let key: [u32; 8] = KEY
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let nonce: [u32; 4] = INPUT
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let output: [u32; 8] = OUTPUT
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let actual = hchacha(ChaChaKey(key), HChaChaNonce(nonce));
            assert_eq!(actual.0, output);
        }
    }
}

///// end   unfortunate vendored XChaCha20 impl //////

fn argon2i_config() -> argon2::Params {
    argon2::Params::new(1 << 14, 1, 2, Some(64)).unwrap()
}

fn argon2id_config() -> argon2::Params {
    argon2::Params::new(1 << 13, 2, 2, Some(64)).unwrap()
}

fn key2b<N>(k: &[u8; 64], data: &[&[u8]]) -> GenericArray<u8, N>
where
    N: ArrayLength<u8> + IsLessOrEqual<U64>,
    LeEq<N, U64>: NonZero,
{
    // let mut hasher = Blake2bMac::<N>::new_with_salt_and_personal(
    //     k,
    //     &[],
    //     "sCrOmB2EnCrYpToR".as_bytes(),
    // )

    let mut hasher = blake2b_simd::Params::new()
        .hash_length(N::to_usize())
        .key(k)
        .personal("sCrOmB2EnCrYpToR".as_bytes())
        .to_state();
    for d in data {
        hasher.update(d);
    }
    <&GenericArray<u8, N>>::from(hasher.finalize().as_bytes()).clone()
}

// struct RootKey(Zeroizing<Secret<[u8; 64]>>);
#[derive(Clone, Copy)]
struct RootKeyInner([u8; 64]);
impl Default for RootKeyInner {
    fn default() -> Self {
        Self([0u8; 64])
    }
}
impl zeroize::DefaultIsZeroes for RootKeyInner {}
struct RootKey(SecretBox<RootKeyInner>);

struct Passphrase(SecretString);
#[derive(Clone)]
// struct Nonce(chacha20::XNonce);
struct Nonce([u8; 24]);
#[derive(Clone)]
struct NonceBlock(Nonce, [u8; 40]);
struct Salt([u8; 64]);

// TODO: figure out how to zeroize these and pin them in place.
//       It isn't obvious that we can even pin all these.
// type HmacState = Box<Blake2bMac<U64>>;
type HmacState = Box<blake2b_simd::State>;
// type CipherState = Box<chacha20::XChaCha20>;

impl RootKey {
    fn new(pass: Passphrase, salt: &Salt) -> Self {
        // NOTE: I have no idea how to determine if this
        // local-to-a-function use of secrets is safe. Without clear
        // guarantees from LLVM, the compiler or the OS can write these out
        // to a random spot in memory and never clear it.

        let hash_with_tag = |a2: argon2::Argon2, tag: &'static str| {
            let mut ret = [0u8; 64];
            a2.hash_password_into(
                pass.0.expose_secret().as_bytes(),
                &key2b::<U64>(&salt.0, &[tag.as_bytes().as_ref()]),
                &mut ret,
            )
            .unwrap();
            ret
        };

        let rk_i = {
            let a2i = argon2::Argon2::new(
                argon2::Algorithm::Argon2i,
                argon2::Version::V0x13,
                argon2i_config(),
            );
            hash_with_tag(a2i, "argon2i")
        };

        let rk_id = {
            let a2id = argon2::Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2id_config(),
            );
            hash_with_tag(a2id, "argon2id")
        };

        Self(SecretBox::<RootKeyInner>::init_with_mut(|rk| {
            rk.0.copy_from_slice(
                key2b::<U64>(
                    &[0u8; 64],
                    &["root".as_bytes(), &rk_i, &rk_id],
                )
                .as_slice(),
            )
        }))
    }

    fn create_states(
        self,
        nonce: Nonce,
    ) -> (Box<chacha::CipherState>, HmacState) {
        let hmac_key =
            key2b::<U64>(&self.0.expose_secret().0, &["hmac".as_bytes()]);
        let hmac = Box::new(
            blake2b_simd::Params::new()
                .hash_length(64)
                .key(&hmac_key)
                .personal("sCrOmB2AuThEnTiC".as_bytes())
                .to_state(),
        );
        let cipher_key = key2b::<U32>(
            &self.0.expose_secret().0,
            &["encrypt".as_bytes()],
        );

        // let cipher = Box::new(<chacha20::XChaCha20 as cipher::KeyIvInit>::new(

        let cipher = Box::new(chacha::CipherState::new(
            &<[u8; 32]>::from(cipher_key),
            &nonce.0,
        ));
        (cipher, hmac)
    }
}

fn scromble<R, W>(
    pw: Passphrase,
    max_pad_factor: Option<f32>,
    mut reader: Box<R>,
    mut writer: Box<W>,
) -> Result<(), Box<dyn std::error::Error>>
where
    W: std::io::Write + ?Sized,
    R: std::io::Read + ?Sized,
{
    let mut prng = ChaCha20Rng::from_entropy();
    let salt = {
        let mut ret = [0u8; 64];
        prng.fill_bytes(&mut ret);
        Salt(ret)
    };
    let nonce = {
        let mut nonce_buf = [0u8; 24];
        let mut rest_buf = [0u8; 40];

        prng.fill_bytes(&mut nonce_buf);
        prng.fill_bytes(&mut rest_buf);

        // NonceBlock(Nonce(chacha20::XNonce::clone_from_slice(&nonce_buf)), rest_buf)
        NonceBlock(Nonce(nonce_buf), rest_buf)
    };

    let (mut cipher, mut mac_state) =
        RootKey::new(pw, &salt).create_states(nonce.0.clone());

    let mut buffer = [0u8; 64 << 10];

    let mut write_data =
        |buf: &[u8]| -> Result<(), Box<dyn std::error::Error>> {
            writer.write_all(buf)?;
            mac_state.update(buf);
            Ok(())
        };

    // write SB
    write_data(&salt.0)?;

    // write NB (beginning of CC)
    {
        let nonce_len = (nonce.0).0.len();
        let nonce_extra_len = nonce.1.len();
        assert_eq!(nonce_len + nonce_extra_len, 64);

        write_data(&(nonce.0).0)?;

        write_data(&nonce.1)?;
    }

    let mut bytes_written = 0usize;

    // write the rest of the core ciphertext
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                break;
            }
            Ok(bytes_read) => {
                let ct_buf = &mut buffer[..bytes_read];
                cipher.try_apply_keystream(ct_buf)?;

                write_data(ct_buf)?;
                bytes_written = bytes_written
                    .checked_add(ct_buf.len())
                    .ok_or(ScrombleError::Overflow)?;
            }
            Err(e) => {
                if ErrorKind::Interrupted != e.kind() {
                    return Err(e.into());
                }
            }
        }
    }

    // calculate MAXPAD
    let max_pad: f32 = max_pad_factor.unwrap_or_else(|| {
        if bytes_written > 65536 {
            0.2
        } else if bytes_written <= 2048 {
            1.0
        } else {
            1.0 - 0.8 * ((bytes_written as f32) - 2048f32)
                / (65536f32 - 2048f32)
        }
    });

    let max_pad_length = <u64 as ApproxFrom<f32>>::approx_from(
        max_pad * max(64, bytes_written) as f32,
    )?;
    let max_pad_length = max(max_pad_length, 1);

    // I'm not worried about the tiny bias here
    let pad_len = prng.next_u64() % max_pad_length;

    // write out padding
    let mut remaining_pad = pad_len;
    while remaining_pad > 0 {
        let bytes_to_add = min(buffer.len(), remaining_pad as usize);

        let buf = &mut buffer[..bytes_to_add];
        buf.fill(0);
        cipher.try_apply_keystream(buf)?;
        write_data(buf)?;
        remaining_pad -= buf.len() as u64;
    }

    // write out length
    let mut length_bytes = (bytes_written as u64).to_le_bytes();
    cipher.try_apply_keystream(&mut length_bytes)?;
    write_data(&length_bytes)?;

    // write out the mac (we're done!)
    // writer.write_all(mac_state.finalize_fixed().as_slice())?;
    writer.write_all(mac_state.finalize().as_bytes())?;

    writer.flush()?;

    Ok(())
}

const HMAC_SIZE: usize = 64;

struct HmacTable<R: std::io::Read + std::io::Seek + ?Sized> {
    bytes_remaining: u64,
    block_size: u64,
    // hashes_reversed: Vec<digest::Output<blake2b_simd::State>>,
    hashes_reversed: Vec<[u8; 64]>,
    bytes_in_buffer: u64,
    inner_buffer: Vec<u8>,
    hmac: HmacState,
    reader: Box<R>,
}

impl<R: std::io::Read + std::io::Seek + ?Sized> HmacTable<R> {
    fn new(
        mut hmac: HmacState,
        mut reader: Box<R>,
    ) -> Result<(Self, u64, [u8; 8]), Box<dyn std::error::Error>> {
        let init_hmac = hmac.clone();
        let mut block_size = 4 << 10;
        let mut total_bytes_read = 0u64;

        let mut buf = vec![0; block_size + HMAC_SIZE];
        let mut bytes_in_buf = 0;
        let mut last_8_bytes = [0u8; 8];

        let mut prefix_hashes = vec![];

        loop {
            match reader.read(&mut buf[bytes_in_buf..]) {
                Ok(0) => {
                    break;
                }
                Ok(bytes_read) => {
                    bytes_in_buf += bytes_read;
                    total_bytes_read += bytes_read as u64;
                    if bytes_in_buf == buf.len() {
                        hmac.update(&buf[..block_size]);
                        // prefix_hashes.push(hmac.clone().finalize_fixed());
                        prefix_hashes
                            .push(*hmac.clone().finalize().as_array());

                        last_8_bytes.copy_from_slice(
                            &buf[block_size - 8..block_size],
                        );
                        let hmac_part: [u8; HMAC_SIZE] =
                            (&buf[block_size..]).try_into().unwrap();
                        bytes_in_buf = hmac_part.len();
                        buf[..bytes_in_buf].copy_from_slice(&hmac_part);

                        if prefix_hashes.len() % 2 == 0
                            && prefix_hashes.len() / 2
                                >= block_size / HMAC_SIZE
                        {
                            block_size *= 2; // TODO: checked
                            for i in 0..prefix_hashes.len() / 2 {
                                prefix_hashes[i] =
                                    prefix_hashes[2 * i + 1];
                            }
                            prefix_hashes.resize(
                                prefix_hashes.len() / 2,
                                // Default::default(),
                                [0; 64],
                            );
                            buf.resize(block_size + HMAC_SIZE, 0);
                        }
                    }
                }
                Err(e) => {
                    if ErrorKind::Interrupted != e.kind() {
                        return Err(e.into());
                    }
                }
            }
        }

        if total_bytes_read < 64 + 24 + 40 + 8 + 64 {
            return Err(ScrombleError::TooShort.into());
        }

        assert!(bytes_in_buf >= HMAC_SIZE);

        hmac.update(&buf[..(bytes_in_buf - HMAC_SIZE)]);

        if bytes_in_buf >= HMAC_SIZE {
            let l8b_included = min(8, bytes_in_buf - HMAC_SIZE);
            let buf_end = bytes_in_buf - HMAC_SIZE;

            last_8_bytes[8 - l8b_included..]
                .copy_from_slice(&buf[buf_end - l8b_included..buf_end]);
        }

        // let final_mac = hmac.finalize_fixed();
        let final_mac = *hmac.finalize().as_array();

        if !<bool>::from(
            final_mac
                .as_slice()
                .ct_eq(&buf[bytes_in_buf - HMAC_SIZE..bytes_in_buf]),
        ) {
            return Err(ScrombleError::BadHmac.into());
        }

        prefix_hashes.push(final_mac);

        prefix_hashes.reverse();

        reader.rewind()?;

        Ok((
            Self {
                bytes_remaining: total_bytes_read,
                block_size: block_size.try_into().unwrap(),
                hashes_reversed: prefix_hashes,
                inner_buffer: vec![0u8; block_size + HMAC_SIZE],
                hmac: init_hmac,
                reader,
                bytes_in_buffer: 0,
            },
            total_bytes_read,
            last_8_bytes,
        ))
    }

    fn next(
        &mut self,
        mut buffer: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        if self.bytes_remaining == 0 {
            return Ok(None);
        }

        buffer.resize(self.block_size as usize + HMAC_SIZE, 0);
        let mut buffer =
            core::mem::replace(&mut self.inner_buffer, buffer);
        assert_eq!(buffer.len(), self.block_size as usize + HMAC_SIZE);

        loop {
            match self
                .reader
                .read(&mut buffer[self.bytes_in_buffer as usize..])
            {
                Ok(0) => {
                    break;
                }
                Ok(bytes_read) => {
                    self.bytes_in_buffer += bytes_read as u64;
                    self.bytes_remaining = self
                        .bytes_remaining
                        .checked_sub(bytes_read as u64)
                        .ok_or(ScrombleError::FileChanged)?;

                    if self.bytes_in_buffer == buffer.len() as u64 {
                        self.hmac
                            .update(&buffer[..self.block_size as usize]);

                        let hmac_part: [u8; HMAC_SIZE] = (&buffer
                            [self.block_size as usize..])
                            .try_into()
                            .unwrap();

                        let segment_hash: [u8; HMAC_SIZE] =
                            *self.hmac.clone().finalize().as_array();
                        // self.hmac.clone().finalize_fixed().into();
                        let expected_hash = self
                            .hashes_reversed
                            .pop()
                            .ok_or(ScrombleError::FileChanged)?;
                        if !bool::from(
                            segment_hash.as_slice().ct_eq(&expected_hash),
                        ) {
                            return Err(ScrombleError::FileChanged.into());
                        }

                        self.inner_buffer[..HMAC_SIZE]
                            .copy_from_slice(&hmac_part);
                        self.bytes_in_buffer = HMAC_SIZE as u64;

                        buffer.resize(self.block_size as usize, 0);

                        return Ok(Some(buffer));
                    }
                }
                Err(e) => {
                    if ErrorKind::Interrupted != e.kind() {
                        return Err(e.into());
                    }
                }
            }
        }

        if self.bytes_remaining > 0 || self.hashes_reversed.len() != 1 {
            return Err(ScrombleError::FileChanged.into());
        }

        assert!(self.bytes_in_buffer >= HMAC_SIZE as u64);
        self.hmac
            .update(&buffer[..self.bytes_in_buffer as usize - HMAC_SIZE]);

        // let final_mac = self.hmac.clone().finalize_fixed();
        let final_mac = *self.hmac.clone().finalize().as_array();
        // can be an unwrap()
        let final_hash = self
            .hashes_reversed
            .pop()
            .ok_or(ScrombleError::FileChanged)?;

        if !<bool>::from(final_mac.as_slice().ct_eq(final_hash.as_slice()))
        {
            return Err(ScrombleError::FileChanged.into());
        }

        if !<bool>::from(final_mac.as_slice().ct_eq(
            &buffer[self.bytes_in_buffer as usize - HMAC_SIZE
                ..self.bytes_in_buffer as usize],
        )) {
            return Err(ScrombleError::FileChanged.into());
        }

        buffer.resize(self.bytes_in_buffer as usize - HMAC_SIZE, 0);
        Ok(Some(buffer))
    }
}

fn descromble<R, W>(
    pw: Passphrase,
    mut reader: Box<R>,
    mut writer: Box<W>,
) -> Result<(), Box<dyn std::error::Error>>
where
    W: std::io::Write + ?Sized,
    R: std::io::Read + std::io::Seek + ?Sized,
{
    let salt = {
        let mut ret = [0u8; 64];

        reader.read_exact(&mut ret)?;
        Salt(ret)
    };

    let nonce = {
        let mut ret = [0u8; 24];

        reader.read_exact(&mut ret)?;
        Nonce(ret.into())
    };

    let (cipher, mac_state) =
        RootKey::new(pw, &salt).create_states(nonce.clone());

    reader.rewind()?;

    let (mut mac_table, total_size, mut last_8) =
        HmacTable::new(mac_state, reader)?;
    let mut cipher = cipher;

    let mut buf = vec![];
    let mut is_first = true;
    let mut correct_size = 0;
    let mut bytes_written = 0;
    while let Some(block) = mac_table.next(core::mem::take(&mut buf))? {
        buf = block;

        let output_slice: &mut [u8] = if is_first {
            is_first = false;
            if &buf[..64] != &salt.0 || &buf[64..88] != nonce.0.as_slice()
            {
                return Err(ScrombleError::FileChanged.into());
            }

            {
                cipher.try_seek(total_size - 128 - 64 - 8)?;
                cipher.try_apply_keystream(&mut last_8).unwrap();
                correct_size = u64::from_le_bytes(last_8);
                assert!(correct_size <= total_size - 128 - 64 - 8);
                cipher.try_seek(0u64)?;
            }

            &mut buf[128..]
        } else {
            &mut buf
        };

        let amount_to_write =
            min(output_slice.len(), correct_size as usize - bytes_written);
        cipher
            .try_apply_keystream(&mut output_slice[..amount_to_write])?;
        writer.write_all(&output_slice[..amount_to_write])?;
        bytes_written += amount_to_write;
    }

    writer.flush()?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use quickcheck::Arbitrary;
    use quickcheck_macros::quickcheck;

    #[derive(Debug, Clone)]
    struct ScrombleFile {
        pw: String,
        max_pad_factor: Option<f32>,
        plaintext: Vec<u8>,
    }

    impl Arbitrary for ScrombleFile {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let pw = String::arbitrary(g).into();
            let max_pad_factor = if bool::arbitrary(g) {
                Some((u16::arbitrary(g) as f32) / (u16::MAX as f32))
            } else {
                None
            };
            let plaintext: Vec<u8> = <_>::arbitrary(g);
            Self {
                pw,
                max_pad_factor,
                plaintext,
            }
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            Box::new(
                self.plaintext
                    .shrink()
                    .map({
                        let zelf = self.clone();
                        move |plaintext| Self {
                            pw: zelf.pw.clone(),
                            max_pad_factor: zelf.max_pad_factor.clone(),
                            plaintext,
                        }
                    })
                    .chain(self.max_pad_factor.shrink().map({
                        let zelf = self.clone();
                        move |max_pad_factor| Self {
                            pw: zelf.pw.clone(),
                            max_pad_factor,
                            plaintext: zelf.plaintext.clone(),
                        }
                    }))
                    .chain(self.pw.shrink().map({
                        let zelf = self.clone();
                        move |pw| Self {
                            pw,
                            max_pad_factor: zelf.max_pad_factor.clone(),
                            plaintext: zelf.plaintext.clone(),
                        }
                    })),
            )
        }
    }

    #[quickcheck]
    fn enc_dec_loop(file: ScrombleFile) {
        let mut enc_file = vec![];
        scromble(
            Passphrase(file.pw.clone().into()),
            file.max_pad_factor,
            Box::new(&file.plaintext[..]),
            Box::new(&mut enc_file),
        )
        .unwrap();
        let enc_file_len = enc_file.len() as f32;
        let max_pad_factor = file.max_pad_factor.unwrap_or(1.0f32);
        let enc_file_len_limit = (1f32 + max_pad_factor)
            * (file.plaintext.len() as f32)
            + (4 * 64 + 8) as f32;
        assert!(
            enc_file_len <= enc_file_len_limit,
            "{} <= {}",
            enc_file_len,
            enc_file_len_limit
        );
        let mut dec_file = vec![];
        descromble(
            Passphrase(file.pw.into()),
            Box::new(std::io::Cursor::new(&enc_file)),
            Box::new(&mut dec_file),
        )
        .unwrap();
        assert_eq!(file.plaintext, dec_file);
    }

    #[quickcheck]
    fn decrypt_authentic(
        corruption_mask: (u8, Vec<u8>),
        corruption_pos: u16,
        file: ScrombleFile,
    ) {
        let mut enc_file = vec![];
        scromble(
            Passphrase(file.pw.clone().into()),
            file.max_pad_factor,
            Box::new(&file.plaintext[..]),
            Box::new(&mut enc_file),
        )
        .unwrap();

        let corruption_pos = (corruption_pos as usize) % enc_file.len();
        for (i, x) in core::iter::once(corruption_mask.0)
            .chain((corruption_mask.1).into_iter())
            .enumerate()
        {
            let ix = corruption_pos + i;
            if ix >= enc_file.len() {
                break;
            }
            enc_file[corruption_pos + i] ^= x;
        }

        let mut dec_file = vec![];
        descromble(
            Passphrase(file.pw.into()),
            Box::new(std::io::Cursor::new(&enc_file)),
            Box::new(&mut dec_file),
        )
        .unwrap_err();
    }

    #[quickcheck]
    fn decrypt_wrong_pw(wrong_pw: String, file: ScrombleFile) {
        let mut enc_file = vec![];
        scromble(
            Passphrase(file.pw.clone().into()),
            file.max_pad_factor,
            Box::new(&file.plaintext[..]),
            Box::new(&mut enc_file),
        )
        .unwrap();

        let mut dec_file = vec![];
        descromble(
            Passphrase(wrong_pw.into()),
            Box::new(std::io::Cursor::new(&enc_file)),
            Box::new(&mut dec_file),
        )
        .unwrap_err();
    }

    // TODO: come up with better statistical tests
    #[quickcheck]
    fn encrypt_uncorrelated(file: ScrombleFile) {
        let mut enc_file1 = vec![];
        scromble(
            Passphrase(file.pw.clone().into()),
            file.max_pad_factor,
            Box::new(&file.plaintext[..]),
            Box::new(&mut enc_file1),
        )
        .unwrap();
        let mut enc_file2 = vec![];
        scromble(
            Passphrase(file.pw.clone().into()),
            file.max_pad_factor,
            Box::new(&file.plaintext[..]),
            Box::new(&mut enc_file2),
        )
        .unwrap();

        assert!(enc_file1.len() < u32::MAX as usize);

        let mut hist1 = [0usize; 256];
        let mut hist1_samples = 0usize;
        let mut hist2 = [0usize; 256];
        let mut hist2_samples = 0usize;
        let mut hist_diff = [0usize; 256];
        let mut hist_diff_samples = 0usize;

        for i in 0..max(enc_file1.len(), enc_file2.len()) {
            if i < enc_file1.len() {
                if i < enc_file2.len() {
                    hist_diff_samples += 1;
                    hist_diff[enc_file1[i].wrapping_sub(enc_file2[i])
                        as usize] += 1;
                }

                hist1_samples += 1;
                hist1[enc_file1[i] as usize] += 1;
            }

            if i < enc_file2.len() {
                hist2_samples += 1;
                hist2[enc_file2[i] as usize] += 1;
            }
        }

        let hists = vec![
            (hist1_samples, hist1),
            (hist2_samples, hist2),
            (hist_diff_samples, hist_diff),
        ];

        for (i, (n, hist)) in hists.into_iter().enumerate() {
            assert!(n > 0);
            let mut ent = 0f64;
            for c in hist {
                let p = (c as f64) / (n as f64);
                let lg_p = p.log2();
                if lg_p.is_finite() {
                    ent += -(p * lg_p / 8f64);
                }
            }

            assert!(ent > 0.85, "{}: ent = {}", i, ent);
        }
    }
}

#[derive(Debug, clap::StructOpt)]
#[structopt(name = "scromble",
about = concat!(
"Symmetric, randomized, authenticated encryption/decryption\n\n",
"Passphrases are read from stdin (until newline or eof).\n",
"Outputs are written to stdout (non-windows only) or `outfile`.\n",
"Algorithms: argon2 (pbkdf), xchacha20 (stream cipher), blake2b (kdf,hmac).\n",
"Run with `explain-design` for more details\n\n",
)
)]
enum Command {
    /// Encrypt and MAC with fresh randomness.
    Encrypt {
        /// Maximum pad/file-size ratio. Defaults somewhere between 0.2 and
        /// 1.0 (see `explain-design`)
        #[structopt(long)]
        max_pad_factor: Option<f32>,

        /// The file to be encrypted and MACd
        #[structopt(parse(from_os_str))]
        file: PathBuf,

        /// The output file (stdout if not provided)
        #[structopt(parse(from_os_str))]
        #[cfg(target_os = "windows")]
        outfile: PathBuf,
        #[cfg(not(target_os = "windows"))]
        outfile: Option<PathBuf>,
    },

    /// Check the MAC and decrypt with the older encryption scheme. Returns
    /// a nonzero error if anything fails.
    Decrypt {
        /// The file to be checked and decrypted
        #[structopt(parse(from_os_str))]
        file: PathBuf,

        /// The output file (stdout if not provided)
        #[structopt(parse(from_os_str))]
        #[cfg(target_os = "windows")]
        outfile: PathBuf,
        #[cfg(not(target_os = "windows"))]
        outfile: Option<PathBuf>,
    },

    /// Print the `scromble` DESIGN.md document.
    ExplainDesign,

    /// Generate a shell completion file.
    GenCompletion {
        /// Which shell to generate completions for (leave empty to list
        /// the available options)
        which_shell: Option<String>,

        /// Where to put the completions
        #[structopt(parse(from_os_str))]
        outdir: Option<PathBuf>,
    },
}

// #[test]
// fn all_sizes_agree() {
//     assert_eq!(blake2b_simd::OUTBYTES, chacha20::BLOCK_SIZE);
// }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Command::from_args();

    match &args {
        Command::ExplainDesign => {
            let design_str = include_str!("../DESIGN.md");
            print!("{design_str}");
            return Ok(());
        }

        Command::GenCompletion {
            which_shell: None, ..
        } => {
            for x in Shell::value_variants() {
                println!("{x}");
            }
            return Ok(());
        }

        Command::GenCompletion {
            which_shell: Some(shell),
            outdir,
        } => {
            let shell = Shell::from_str(shell, true)?;
            match outdir {
                None => {
                    generate(
                        shell,
                        &mut Command::clap(),
                        "scromble",
                        &mut std::io::stdout(),
                    );
                }
                Some(outdir) => {
                    generate_to(
                        shell,
                        &mut Command::clap(),
                        "scromble",
                        outdir,
                    )?;
                }
            }
            return Ok(());
        }

        _ => {}
    }

    let password = Passphrase(rpassword::read_password()?.into());

    let stdout = std::io::stdout();
    let open_outfile =
        |outfile: _| -> Result<Box<dyn Write>, std::io::Error> {
            #[cfg(target_os = "windows")]
            let outfile = Some(outfile);

            let ret: Box<dyn Write> = if let Some(outfile) = outfile {
                Box::new(File::create(outfile)?) as Box<dyn Write>
            } else {
                Box::new(stdout.lock()) as Box<dyn Write>
            };
            Ok(ret)
        };

    match args {
        Command::Encrypt {
            max_pad_factor,
            file,
            outfile,
        } => {
            scromble(
                password,
                max_pad_factor,
                Box::new(File::open(&file)?),
                open_outfile(outfile)?,
            )?;
        }

        Command::Decrypt { file, outfile } => {
            descromble(
                password,
                Box::new(File::open(&file)?),
                open_outfile(outfile)?,
            )?;
        }

        _ => {
            unimplemented!();
        }
    }
    Ok(())
}
