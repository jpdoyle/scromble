#[test]
fn argon2i_config() {
    use argon2::{Config, ThreadMode, Variant, Version};

    let config = Config::default();
    assert_eq!(config.ad, &[]);
    assert_eq!(config.hash_length, 32);
    assert_eq!(config.lanes, 1);
    assert_eq!(config.mem_cost, 4096);
    assert_eq!(config.secret, &[]);
    assert_eq!(config.thread_mode, ThreadMode::Sequential);
    assert_eq!(config.time_cost, 3);
    assert_eq!(config.variant, Variant::Argon2i);
    assert_eq!(config.version, Version::Version13);
}

#[derive(Zeroize, Clone)]
enum Block([u8; chacha20::BLOCK_SIZE]);

impl Block {
    fn new_random() -> Self {
        let mut ret = Self::zero();
        thread_rng().fill_bytes(&mut ret.0);
        ret
    }
    fn zero() -> Self {
        Self([0u8; chacha20::BLOCK_SIZE])
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct Passphrase(String);

// 512 bits
struct Salt(Block);

impl Salt {
    fn new_random() -> Self {
        let mut ret = Salt(Block::zero());
        thread_rng().fill_bytes(&mut (ret.0).0);
        ret
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct Key(chacha20::Key);

#[derive(Zeroize)]
#[zeroize(drop)]
struct Plaintext(Block);

const BLOCKS_PER_STEP: u64 = core::u32::MAX as u64 / 2;

// NOTE: this is only necessary in "legacy" mode now that XChaCha20
// properly supports the full 64-bit keystream
fn refresh_cipher(cipher: &mut chacha20::XChaCha20) -> Result<(), Box<dyn std::error::Error>> {
    let mut new_key = Key(Default::default());
    let mut new_nonce = Nonce(Default::default());
    cipher.try_apply_keystream(&mut new_key.0)?;
    cipher.try_apply_keystream(&mut new_nonce.0)?;
    *cipher = chacha20::XChaCha20::new(&new_key.0, &new_nonce.0);
    Ok(())
}

impl Plaintext {
    fn encrypt(
        mut self,
        cipher: &mut chacha20::XChaCha20,
        mut blocks_avail: Option<&mut u64>,
    ) -> Result<Ciphertext, Box<dyn std::error::Error>> {
        let mut blk = mem::replace(&mut self.0, Block::zero());
        if let Some(ref mut blocks_avail) = blocks_avail {
            if **blocks_avail == 0 {
                refresh_cipher(cipher)?;
                **blocks_avail = BLOCKS_PER_STEP;
            }
        }

        // cipher.apply_keystream(&mut blk.0);
        cipher.try_apply_keystream(&mut blk.0)?;
        if let Some(blocks_avail) = blocks_avail {
            *blocks_avail -= 1;
        }

        Ok(Ciphertext(blk))
    }
}

#[derive(Clone)]
struct Ciphertext(Block);

impl Ciphertext {
    fn decrypt(
        self,
        cipher: &mut chacha20::XChaCha20,
        mut blocks_avail: Option<&mut u64>,
    ) -> Result<Plaintext, Box<dyn std::error::Error>> {
        let mut blk = self.0;
        if let Some(ref mut blocks_avail) = blocks_avail {
            if **blocks_avail == 0 {
                refresh_cipher(cipher)?;
                **blocks_avail = BLOCKS_PER_STEP;
            }
        }

        // cipher.apply_keystream(&mut blk.0);
        cipher.try_apply_keystream(&mut blk.0)?;
        if let Some(blocks_avail) = blocks_avail {
            *blocks_avail -= 1;
        }
        Ok(Plaintext(blk))
    }
}

// the blake2b module doesn't have a way to zeroize it, so we fill it with
// some junk instead
fn blake2b_finalize(mut mac_state: blake2b_simd::State) {
    let mut random_extra = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut random_extra);
    mac_state.update(&random_extra);
    // hopefully this is enough to keep the compiler from noticing
    // it can elide those writes
    for b in mac_state.finalize().as_array().iter() {
        black_box(*b);
    }
}

struct Nonce(chacha20::XNonce);

impl Nonce {
    fn new_random() -> Self {
        let mut ret = Self(Default::default());
        thread_rng().fill_bytes(&mut ret.0);
        ret
    }
}

// Needs to be zeroize-on-drop for chosen-ciphertext reasons. If Alice can
// convince Bob to try decrypting a message from her with an incorrect MAC,
// Bob still calculates the correct MAC in memory.
#[derive(Zeroize)]
#[zeroize(drop)]
#[allow(clippy::upper_case_acronyms)]
struct MAC(Block);

#[test]
fn all_sizes_agree() {
    assert_eq!(blake2b_simd::OUTBYTES, chacha20::BLOCK_SIZE);
}

fn derive_key(pw: Passphrase, s: &Salt) -> Result<Key, Box<dyn std::error::Error>> {
    let slice = Zeroizing::new(argon2::hash_raw(
        pw.0.as_bytes(),
        &(s.0).0,
        &argon2::Config::default(),
    )?);
    Ok(Key(generic_array::GenericArray::<_, _>::clone_from_slice(
        slice.as_slice(),
    )))
}

fn derive_cipher_and_mac(
    pw: Passphrase,
    salt: &Salt,
    nonce: &Nonce,
) -> Result<(chacha20::XChaCha20, blake2b_simd::State), Box<dyn std::error::Error>> {
    let mut cipher = {
        let key = derive_key(pw, salt)?;
        chacha20::XChaCha20::new(&key.0, &nonce.0)
    };

    let mac_key = {
        let mut ret = Key(Default::default());
        cipher.try_apply_keystream(&mut ret.0)?;
        ret
    };

    let mac_state = blake2b_simd::Params::new()
        .hash_length(blake2b_simd::OUTBYTES)
        .personal(b"sCrOmBlEnCrYpToR")
        .key(&mac_key.0)
        .to_state();

    Ok((cipher, mac_state))
}


