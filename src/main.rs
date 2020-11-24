#![deny(warnings)]
#![allow(dead_code)]
use std::path::PathBuf;
use structopt::StructOpt;
use zeroize::{Zeroize, Zeroizing};
// use chacha20::XChaCha20;
use rand::thread_rng;
use rand::RngCore;
use std::convert::TryInto;
use chacha20::cipher::{NewStreamCipher, SyncStreamCipher,
    SyncStreamCipherSeek};
use std::mem;
use std::fs::File;
use std::fmt;
use std::io::Seek;
use std::io::SeekFrom;

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

#[derive(Debug, StructOpt)]
#[structopt(name = "scromble",
about = concat!(
"Symmetric, randomized, authenticated encryption/decryption\n\n",
"Passphrases are read from stdin (until newline or eof).\n",
"Outputs are written to stdout.\n",
"Algorithms: argon2i (kdf), chacha20 (stream cipher), blake2b (hmac)\n\n",
"WARNING: if the file is changed while scromble is reading it, bad\n",
"things could happen!",
)
)]
enum Command {
    /// Encrypt and MAC with fresh randomness.
    Encrypt {
        /// The file to be encrypted and MACd
        #[structopt(parse(from_os_str))]
        file: PathBuf,
    },

    /// Check the MAC and decrypt. Returns a nonzero error if anything
    /// fails.
    Decrypt {
        /// The file to be checked and decrypted
        #[structopt(parse(from_os_str))]
        file: PathBuf,
    },
}

#[derive(Zeroize,Clone)]
struct Block([u8;chacha20::BLOCK_SIZE]);

impl Block {
    fn new_random() -> Self {
        let mut ret = Self::zero();
        thread_rng().fill_bytes(&mut ret.0);
        ret
    }
    fn zero() -> Self {
        Self([0u8;chacha20::BLOCK_SIZE])
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct Passphrase(String);

// 256 bits
struct Salt(Block);

impl Salt {
    fn new_random() -> Self {
        let mut ret = Salt(Block::zero());
        thread_rng().fill_bytes(&mut (ret.0).0);
        ret
    }
}

#[derive(Debug)]
enum ScrombleError {
    BadHmac,
    BadLength,
}

impl fmt::Display for ScrombleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScrombleError::BadHmac => {
                write!(f, "Ciphertext has an invalid HMAC")
            },
            ScrombleError::BadLength => {
                write!(f, "Ciphertext has an invalid length")
            },
        }
    }
}

impl std::error::Error for ScrombleError {

}

#[derive(Zeroize)]
#[zeroize(drop)]
struct Key(chacha20::Key);

#[derive(Zeroize)]
#[zeroize(drop)]
struct Plaintext(Block);

impl Plaintext {
    fn encrypt(mut self,  cipher: &mut chacha20::XChaCha20)
            -> Result<Ciphertext, Box<dyn std::error::Error>> {
        let mut blk = mem::replace(&mut self.0,Block::zero());
        cipher.try_apply_keystream(&mut blk.0)?;
        Ok(Ciphertext(blk))
    }
}

#[derive(Clone)]
struct Ciphertext(Block);

impl Ciphertext {
    fn decrypt(self,  cipher: &mut chacha20::XChaCha20)
            -> Result<Plaintext, Box<dyn std::error::Error>> {
        let mut blk = self.0;
        cipher.try_apply_keystream(&mut blk.0)?;
        Ok(Plaintext(blk))
    }
}

// the blake2b module doesn't have a way to zeroize it, so we fill it with
// some junk instead
fn blake2b_finalize(mut mac_state: blake2b_simd::State) {
    let mut random_extra = [0u8;64];
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
struct MAC(Block);

#[test]
fn all_sizes_agree() {
    assert_eq!(blake2b_simd::OUTBYTES,chacha20::BLOCK_SIZE);
}

fn derive_key(pw: Passphrase, s: &Salt)
        -> Result<Key,Box<dyn std::error::Error>> {
    let slice = Zeroizing::new(
        argon2::hash_raw(&pw.0.as_bytes(),
                         &(s.0).0,&argon2::Config::default())?);
    Ok(Key(generic_array::GenericArray::<_,_>
                        ::clone_from_slice(slice.as_slice())))
}

fn derive_cipher_and_mac(pw: Passphrase, salt: &Salt,nonce: &Nonce)
        -> Result<(chacha20::XChaCha20, blake2b_simd::State),
                  Box<dyn std::error::Error>> {
    let mut cipher = {
        let key = derive_key(pw,&salt)?;
        chacha20::XChaCha20::new(&key.0,&nonce.0)
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

    Ok((cipher,mac_state))
}

struct Scrombler<'a> {
    cipher: chacha20::XChaCha20,
    mac_state: blake2b_simd::State,
    writer: Box<dyn std::io::Write + 'a>,
}

/// From https://docs.rs/subtle/2.3.0/src/subtle/lib.rs.html#138
/// This function is a best-effort attempt to prevent the compiler from
/// knowing anything about the value of the returned `u8`, other than its
/// type.
///
/// Because we want to support stable Rust, we don't have access to inline
/// assembly or test::black_box, so we use the fact that volatile values
/// will never be elided to register values.
///
/// Note: Rust's notion of "volatile" is subject to change over time. While
/// this code may break in a non-destructive way in the future,
/// “constant-time” code is a continually moving target, and this is better
/// than doing nothing.
#[inline(never)]
fn black_box(input: u8) -> u8 {

    unsafe {
        // Optimization barrier
        //
        // Unsafe is ok, because:
        //   - &input is not NULL;
        //   - size of input is not zero;
        //   - u8 is neither Sync, nor Send;
        //   - u8 is Copy, so input is always live;
        //   - u8 type is always properly aligned.
        core::ptr::read_volatile(&input as *const u8)
    }
}

impl<'a> Scrombler<'a> {
    fn new(pw: Passphrase, writer: Box<dyn std::io::Write + 'a>)
            -> Result<Self,Box<dyn std::error::Error>> {
        let salt = Salt::new_random();
        let nonce = Nonce::new_random();


        let (cipher,mac_state) = derive_cipher_and_mac(pw,&salt,&nonce)?;

        let mut ret = Self {
            cipher,
            mac_state,
            writer,
        };

        // Block 1: salt
        ret.internal_write_block(salt.0)?;

        // Block 2: nonce, then random bytes
        {
            let mut block2 = Block::zero();
            assert!(block2.0.len() >= nonce.0.len());
            block2.0[..nonce.0.len()].copy_from_slice(&nonce.0);
            ret.cipher.try_apply_keystream(
                &mut block2.0[nonce.0.len()..])?;
            ret.internal_write_block(block2)?;
        }

        // run the cipher forward until a round number
        {
            let curpos = ret.cipher.try_current_pos::<usize>()?;
            let nextpos = chacha20::BLOCK_SIZE
                *((curpos+chacha20::BLOCK_SIZE-1)/chacha20::BLOCK_SIZE);
            assert!(nextpos >= curpos);
            ret.cipher.try_seek(nextpos)?;
        }

        Ok(ret)
    }

    fn internal_write_block(&mut self, blk: Block)
            -> Result<(),Box<dyn std::error::Error>> {
        self.mac_state.update(&blk.0);
        self.writer.write_all(&blk.0)?;
        Ok(())
    }

    fn encrypt_block(&mut self, blk: Plaintext)
            -> Result<(),Box<dyn std::error::Error>> {
        let ciphertext = blk.encrypt(&mut self.cipher)?;
        self.internal_write_block(ciphertext.0)?;
        Ok(())
    }

    fn encrypt_last_bytes(mut self, blk: Zeroizing<Vec<u8>>)
            -> Result<(),Box<dyn std::error::Error>> {
        assert!(blk.len() <= chacha20::BLOCK_SIZE);
        let num_skipped_bytes = chacha20::BLOCK_SIZE - blk.len();
        // Best to crash if this would fail
        let num_skipped_bytes: u8 = num_skipped_bytes.try_into()?;

        // 2nd-to-last block: the last bytes + zero padding
        //
        // NOTE: we do not (and SHOULD NOT) validate the zero padding on
        // decrypt. For our purposes, the zero padding may as well be
        // random data, but with a stream cipher it doesn't matter much.
        //
        // Data validity ONLY comes from the MAC. Anything else is asking
        // for trouble.
        let blk1 = {
            let mut ret = Plaintext(Block::zero());
            (ret.0).0[..blk.len()].copy_from_slice(&blk);
            ret
        };
        self.encrypt_block(blk1)?;

        let blk2 = {
            let mut ret = Plaintext(Block::zero());
            (ret.0).0[0] = num_skipped_bytes;
            ret
        };
        self.encrypt_block(blk2)?;

        // TODO
        // self.cipher.zeroize();

        let mac = {
            let mut ret = MAC(Block::zero());
            let mac = Zeroizing::new(self.mac_state.finalize().as_array()
                                         .clone());
            assert!(mac.len() == (ret.0).0.len());
            (ret.0).0.copy_from_slice(&*mac);
            ret
        };

        // TODO: is this necessary when encrypting?
        blake2b_finalize(self.mac_state);

        self.writer.write_all(&(mac.0).0)?;

        Ok(())
    }
}

struct Descrombler<'a> {
    // cipher is stepped to prev_prev_block (if some)
    cipher: chacha20::XChaCha20,
    // Keep the prev of each so that you can compare the final hash to the
    // final block
    prev_mac_state: blake2b_simd::State,
    // keep prev 3 since second-to-last has the number of skipped bytes in
    // third-to-last
    //
    // yes, it sucks. Still a little better than remembering if [0] is the
    // newest or the oldest
    prev_blocks: Option<(Ciphertext,Option<(Ciphertext,Option<Ciphertext>)>)>,
    writer: Box<dyn std::io::Write + 'a>,
}

impl<'a> Descrombler<'a> {
    fn add_block(&mut self, blk: Block)
            -> Result<(), Box<dyn std::error::Error>> {
        let blk = Ciphertext(blk);
        match self.prev_blocks.as_mut() {
            None => { self.prev_blocks = Some((blk,None)); }
            Some((prev,rest)) => {
                self.prev_mac_state.update(&(prev.0).0);
                match rest.as_mut() {
                    None => { *rest = Some((prev.clone(),None)); },
                    Some((prevprev,rest)) => {
                        if let Some(prevprevprev) = rest.as_mut() {
                            self.writer
                                .write_all(
                                    &(prevprevprev.clone().decrypt(
                                        &mut self.cipher)?.0).0)?
                        }
                        *rest = Some(prevprev.clone());

                        *prevprev = prev.clone()
                    },
                }
                *prev = blk
            }
        }
        Ok(())
    }

    fn finalize(mut self)
            -> Result<(), Box<dyn std::error::Error>> {
        if let Some((mac_block,
                    Some((skip_block,
                          Some(last_data_block))))) = self.prev_blocks {
            if self.prev_mac_state.finalize() != (mac_block.0).0[..] {
                return Err(ScrombleError::BadHmac.into());
            }
            blake2b_finalize(self.prev_mac_state);
            let last_data_block = last_data_block
                .decrypt(&mut self.cipher)?;
            let skip_block = skip_block.decrypt(&mut self.cipher)?;
            // TODO
            // self.cipher.zeroize();
            // skipping 0 and skipping BLOCK_SIZE are both "reasonable"
            let num_skipped = ((skip_block.0).0[0] as usize)
                            % ((last_data_block.0).0.len()+1);
            let num_not_skipped = (last_data_block.0).0.len()
                                - num_skipped;
            self.writer.write_all(
                &(last_data_block.0).0[..num_not_skipped])?;
            Ok(())
        } else {
            Err(ScrombleError::BadLength.into())
        }
    }
}

// this checks the mac
struct DescrombleCheck<'a> {
    descromble: Descrombler<'a>,
    prev_mac_state: blake2b_simd::State,
    prev_block: Option<Block>,
}

impl<'a> DescrombleCheck<'a> {
    fn new(pw: Passphrase, writer: Box<dyn std::io::Write + 'a>, blk1: Block,
           blk2: Block)
            -> Result<Self,Box<dyn std::error::Error>> {
        let salt = Salt(blk1.clone());
        let nonce = {
            let mut ret = Nonce(Default::default());
            let retlen = ret.0.len();
            ret.0.copy_from_slice(&blk2.0[..retlen]);
            ret
        };

        let (mut cipher, mut mac_state) = derive_cipher_and_mac(pw, &salt,
                                                                &nonce)?;

        // run the cipher forward to match scrombling
        let cipher = {
            let curpos = cipher.try_current_pos::<usize>()?;
            cipher.try_seek(curpos + (blk2.0.len() - nonce.0.len()))?;
            let curpos = cipher.try_current_pos::<usize>()?;
            let nextpos = chacha20::BLOCK_SIZE
                *((curpos+chacha20::BLOCK_SIZE-1)/chacha20::BLOCK_SIZE);
            assert!(nextpos >= curpos);
            cipher.try_seek(nextpos)?;
            cipher
        };
        mac_state.update(&blk1.0);
        mac_state.update(&blk2.0);
        let mac_state = mac_state;

        let ret = DescrombleCheck {
            descromble: Descrombler {
                cipher, prev_mac_state: mac_state.clone(),
                prev_blocks: None,
                writer,
            },
            prev_mac_state: mac_state.clone(),
            prev_block: None,
        };
        Ok(ret)
    }

    fn add_block(&mut self, blk: Block) {
        if let Some(prev) = self.prev_block.as_ref() {
            self.prev_mac_state.update(&prev.0);
        }
        self.prev_block = Some(blk);
    }

    fn finalize(self)
            -> Result<Descrombler<'a>,Box<dyn std::error::Error>> {

        match self.prev_block.as_ref() {
            None => { return Err(ScrombleError::BadLength.into()); }
            Some(prev) => {
                if &self.prev_mac_state.finalize() != &prev.0[..] {
                    return Err(ScrombleError::BadHmac.into());
                }
            }
        }

        blake2b_finalize(self.prev_mac_state);

        Ok(self.descromble)
    }
}

enum BlockRead {
    ReadErr(std::io::Error),
    FullBlock(Zeroizing<Block>),
    FinalBlock(Zeroizing<Vec<u8>>),
}

fn read_block(rd: &mut impl std::io::Read) -> BlockRead {
    use BlockRead::*;
    let mut ret = Block::zero();
    let mut bytes_read = 0;
    while bytes_read < ret.0.len() {
        match rd.read(&mut ret.0[bytes_read..]) {
            Ok(0) => {
                return FinalBlock(ret.0[..bytes_read].iter().cloned()
                                     .collect::<Vec<_>>().into());
            },
            Ok(n) => {
                assert!(n <= ret.0.len()-bytes_read);
                bytes_read += n;
            },
            Err(e) => match e.kind() {
                std::io::ErrorKind::Interrupted => {}, // retry
                _ => { return ReadErr(e); },
            },
        }
    }

    assert!(bytes_read == ret.0.len());

    FullBlock(ret.into())
}

fn main() -> Result<(),Box<dyn std::error::Error>> {
    let args = Command::from_args();
    let password = Passphrase(rpassword::read_password()?);
    let stdout = std::io::stdout();
    let mut stdout_lock = stdout.lock();
    match args {
        Command::Encrypt {
            file,
        } => {
            let mut infile = std::io::BufReader::new(File::open(&file)?);
            let writer = Box::new(&mut stdout_lock);
            let mut scrombler = Scrombler::new(password,writer)?;
            let mut last_block = None;

            while last_block.is_none() {
                match read_block(&mut infile) {
                    BlockRead::ReadErr(e) => { return Err(e.into()); },
                    BlockRead::FullBlock(mut b) => {
                        scrombler.encrypt_block(
                            Plaintext(std::mem::replace(&mut b,
                                                        Block::zero())))?;
                    },
                    BlockRead::FinalBlock(b) => {
                        last_block = Some(b)
                    },
                }
            }

            scrombler.encrypt_last_bytes(last_block.unwrap())?;
        },
        Command::Decrypt {
            file,
        } => {
            let mut infile = std::io::BufReader::new(File::open(&file)?);
            let writer = Box::new(&mut stdout_lock);

            let mut descrombler = {
                let blk1 = match read_block(&mut infile) {
                    BlockRead::ReadErr(e)
                        => Err(Box::<dyn std::error::Error>::from(e)),
                    BlockRead::FullBlock(b) => Ok(b),
                    BlockRead::FinalBlock(_)
                        => Err(ScrombleError::BadLength.into()),
                }?;
                let blk2 = match read_block(&mut infile) {
                    BlockRead::ReadErr(e)
                        => Err(Box::<dyn std::error::Error>::from(e)),
                    BlockRead::FullBlock(b) => Ok(b),
                    BlockRead::FinalBlock(_)
                        => Err(ScrombleError::BadLength.into()),
                }?;
                let mut checker = DescrombleCheck::new(password,writer,
                    (*blk1).clone(), (*blk2).clone())?;
                let mut last_block = None;

                while last_block.is_none() {
                    match read_block(&mut infile) {
                        BlockRead::ReadErr(e) => { return Err(e.into()); },
                        BlockRead::FullBlock(b) => {
                            checker.add_block((*b).clone());
                        },
                        BlockRead::FinalBlock(b) => {
                            last_block = Some(b)
                        },
                    }
                }

                let last_block = last_block.unwrap();
                if !last_block.is_empty() {
                    return Err(ScrombleError::BadLength.into());
                }

                checker.finalize()?
            };

            infile.seek(SeekFrom::Start(0))?;

            {
                let /*blk1*/ _ = match read_block(&mut infile) {
                    BlockRead::ReadErr(e)
                        => Err(Box::<dyn std::error::Error>::from(e)),
                    BlockRead::FullBlock(b) => Ok(b),
                    BlockRead::FinalBlock(_)
                        => Err(ScrombleError::BadLength.into()),
                }?;
                let /*blk2*/ _ = match read_block(&mut infile) {
                    BlockRead::ReadErr(e)
                        => Err(Box::<dyn std::error::Error>::from(e)),
                    BlockRead::FullBlock(b) => Ok(b),
                    BlockRead::FinalBlock(_)
                        => Err(ScrombleError::BadLength.into()),
                }?;

                let mut last_block = None;

                while last_block.is_none() {
                    match read_block(&mut infile) {
                        BlockRead::ReadErr(e) => { return Err(e.into()); },
                        BlockRead::FullBlock(b) => {
                            descrombler.add_block((*b).clone())?;
                        },
                        BlockRead::FinalBlock(b) => {
                            last_block = Some(b)
                        },
                    }
                }

                let last_block = last_block.unwrap();
                if !last_block.is_empty() {
                    return Err(ScrombleError::BadLength.into());
                }

                descrombler.finalize()?;
            }
        },
    }
    Ok(())
}

