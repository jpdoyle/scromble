#![deny(warnings)]

#[cfg(test)]
extern crate quickcheck_macros;

use core::cmp::{min,max};
use secrecy::{Secret,SecretString,ExposeSecret};
use std::path::PathBuf;
use structopt::StructOpt;
// use zeroize::Zeroizing;
use blake2::Blake2bMac;
use rand_chacha::ChaCha20Rng;
use cipher::{StreamCipher,StreamCipherSeek};
use typenum::{IsLessOrEqual,LeEq,consts::{U32,U64},NonZero};
use rand::{SeedableRng,RngCore};
// use std::convert::TryInto;
use std::fmt;
use std::fs::File;
use std::io::Seek;
use std::io::Write;
use std::io::ErrorKind;
use generic_array::{GenericArray,ArrayLength};
use subtle::ConstantTimeEq;
use digest::{FixedOutput,Mac};
use conv::ApproxFrom;
use std::convert::TryInto;

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
    let mut hasher =
        Blake2bMac::<N>::new_with_salt_and_personal(k, &[], "sCrOmB2EnCrYpToR".as_bytes()).unwrap();
    for d in data {
        hasher.update(d);
    }
    hasher.finalize_fixed()
}

// struct RootKey(Zeroizing<Secret<[u8; 64]>>);
struct RootKey(Secret<[u8; 64]>);

struct Passphrase(SecretString);
#[derive(Clone)]
struct Nonce(chacha20::XNonce);
#[derive(Clone)]
struct NonceBlock(Nonce, [u8; 40]);
struct Salt([u8; 64]);

// TODO: figure out how to zeroize these and pin them in place.
//       It isn't obvious that we can even pin all these.
type HmacState = Box<Blake2bMac<U64>>;
type CipherState = Box<chacha20::XChaCha20>;

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

        Self(Secret::new(key2b::<U64>(
            &[0u8; 64],
            &["root".as_bytes(), &rk_i, &rk_id],
        ).into()))
    }

    fn create_states(self, nonce: Nonce) -> (CipherState, HmacState) {
        let hmac_key = key2b::<U64>(self.0.expose_secret(), &["hmac".as_bytes()]);
        let hmac = Box::new(Blake2bMac::new_with_salt_and_personal(
            &hmac_key,
            &[],
            "sCrOmB2AuThEnTiC".as_bytes(),
        ).unwrap());
        let cipher_key = key2b::<U32>(self.0.expose_secret(), &["encrypt".as_bytes()]);
        let cipher = Box::new(<chacha20::XChaCha20 as cipher::KeyIvInit>::new(
            &cipher_key,
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

        NonceBlock(Nonce(chacha20::XNonce::clone_from_slice(&nonce_buf)), rest_buf)
    };

    let (mut cipher, mut mac_state) = RootKey::new(pw, &salt).create_states(nonce.0.clone());

    let mut buffer = [0u8; 64 << 10];

    let mut write_data = |buf: &[u8]| -> Result<(), Box<dyn std::error::Error>> {
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
            1.0 - 0.8 * ((bytes_written as f32) - 2048f32) / (65536f32 - 2048f32)
        }
    });

    let max_pad_length = <u64 as ApproxFrom<f32>>::approx_from(max_pad * max(64, bytes_written) as f32)?;
    let max_pad_length = max(max_pad_length,1);

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
    writer.write_all(mac_state.finalize_fixed().as_slice())?;

    writer.flush()?;

    Ok(())
}

const HMAC_SIZE: usize = 64;

struct HmacTable<R: std::io::Read + std::io::Seek + ?Sized> {
    bytes_remaining: u64,
    block_size: u64,
    hashes_reversed: Vec<digest::Output<Blake2bMac<U64>>>,
    bytes_in_buffer: u64,
    inner_buffer: Vec<u8>,
    hmac: HmacState,
    reader: Box<R>,
}

impl<R: std::io::Read + std::io::Seek + ?Sized> HmacTable<R> {
    fn new(mut hmac: HmacState, mut reader: Box<R>) -> Result<(Self,u64,[u8;8]), Box<dyn std::error::Error>> {
        let init_hmac = hmac.clone();
        let mut block_size = 4 << 10;
        let mut total_bytes_read = 0u64;

        let mut buf = vec![0; block_size + HMAC_SIZE];
        let mut bytes_in_buf = 0;
        let mut last_8_bytes = [0u8;8];

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
                        prefix_hashes.push(hmac.clone().finalize_fixed());

                        last_8_bytes.copy_from_slice(&buf[block_size-8..block_size]);
                        let hmac_part: [u8; HMAC_SIZE] = (&buf[block_size..]).try_into().unwrap();
                        bytes_in_buf = hmac_part.len();
                        buf[..bytes_in_buf].copy_from_slice(&hmac_part);

                        if prefix_hashes.len() % 2 == 0
                            && prefix_hashes.len() / 2 >= block_size / HMAC_SIZE
                        {
                            block_size *= 2; // TODO: checked
                            for i in 0..prefix_hashes.len() / 2 {
                                prefix_hashes[i] = prefix_hashes[2 * i + 1];
                            }
                            prefix_hashes.resize(prefix_hashes.len() / 2, Default::default());
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
            let l8b_included = min(8,bytes_in_buf-HMAC_SIZE);
            let buf_end = bytes_in_buf-HMAC_SIZE;

            last_8_bytes[8-l8b_included..].copy_from_slice(&buf[buf_end-l8b_included..buf_end]);
        }

        let final_mac = hmac.finalize_fixed();

        if !<bool>::from(final_mac.as_slice()
            .ct_eq(&buf[bytes_in_buf - HMAC_SIZE..bytes_in_buf]))
        {
            return Err(ScrombleError::BadHmac.into());
        }

        prefix_hashes.push(final_mac);

        prefix_hashes.reverse();

        reader.rewind()?;

        Ok((Self {
            bytes_remaining: total_bytes_read,
            block_size: block_size.try_into().unwrap(),
            hashes_reversed: prefix_hashes,
            inner_buffer: vec![0u8; block_size + HMAC_SIZE],
            hmac: init_hmac,
            reader,
            bytes_in_buffer: 0,
        },total_bytes_read,last_8_bytes))
    }

    fn next(&mut self, mut buffer: Vec<u8>) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        if self.bytes_remaining == 0 {
            return Ok(None);
        }

        buffer.resize(self.block_size as usize + HMAC_SIZE, 0);
        let mut buffer = core::mem::replace(&mut self.inner_buffer, buffer);
        assert_eq!(buffer.len(), self.block_size as usize + HMAC_SIZE);

        loop {
            match self.reader.read(&mut buffer[self.bytes_in_buffer as usize..]) {
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
                        self.hmac.update(&buffer[..self.block_size as usize]);

                        let hmac_part: [u8; HMAC_SIZE] =
                            (&buffer[self.block_size as usize..]).try_into().unwrap();

                        let segment_hash: [u8; HMAC_SIZE] = self.hmac.clone().finalize_fixed().into();
                        let expected_hash =
                            self.hashes_reversed.pop().ok_or(ScrombleError::FileChanged)?;
                        if !bool::from(segment_hash.as_slice().ct_eq(&expected_hash))
                        {
                            return Err(ScrombleError::FileChanged.into());
                        }

                        self.inner_buffer[..HMAC_SIZE].copy_from_slice(&hmac_part);
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
        self.hmac.update(&buffer[..self.bytes_in_buffer as usize - HMAC_SIZE]);

        let final_mac = self.hmac.clone().finalize_fixed();
        // can be an unwrap()
        let final_hash = self
            .hashes_reversed
            .pop()
            .ok_or(ScrombleError::FileChanged)?;

        if !<bool>::from(final_mac.as_slice().ct_eq(final_hash.as_slice())) {
            return Err(ScrombleError::FileChanged.into());
        }

        if !<bool>::from(final_mac.as_slice()
            .ct_eq(&buffer[self.bytes_in_buffer as usize - HMAC_SIZE..self.bytes_in_buffer as usize]))
        {
            return Err(ScrombleError::FileChanged.into());
        }

        buffer.resize(self.bytes_in_buffer as usize - HMAC_SIZE,0);
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

    let (cipher, mac_state) = RootKey::new(pw, &salt).create_states(nonce.clone());

    reader.rewind()?;

    let (mut mac_table,total_size,mut last_8) = HmacTable::new(mac_state, reader)?;
    let mut cipher = cipher;

    let mut buf = vec![];
    let mut is_first = true;
    let mut correct_size = 0;
    let mut bytes_written = 0;
    while let Some(block) = mac_table.next(core::mem::take(&mut buf))? {
        buf = block;

        let output_slice: &mut [u8] = if is_first {
            is_first = false;
            if &buf[..64] != &salt.0 || &buf[64..88] != nonce.0.as_slice() {
                return Err(ScrombleError::FileChanged.into());
            }

            {
                cipher.try_seek(total_size-128-64-8)?;
                cipher.apply_keystream(&mut last_8);
                correct_size = u64::from_le_bytes(last_8);
                assert!(correct_size <= total_size-128-64-8);
                cipher.try_seek(0)?;
            }

            &mut buf[128..]
        } else {
            &mut buf
        };

        let amount_to_write = min(output_slice.len(),correct_size as usize-bytes_written);
        cipher.try_apply_keystream(&mut output_slice[..amount_to_write])?;
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

    #[derive(Debug,Clone)]
    struct ScrombleFile {
        pw: String,
        max_pad_factor: Option<f32>,
        plaintext: Vec<u8>,
    }

    impl Arbitrary for ScrombleFile {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let pw = String::arbitrary(g).into();
            let max_pad_factor = if bool::arbitrary(g) {
                Some((u16::arbitrary(g) as f32)/(u16::MAX as f32))
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
            Box::new(self.plaintext.shrink()
                .map({ let zelf = self.clone();
                    move |plaintext|
                    Self {
                        pw: zelf.pw.clone(),
                        max_pad_factor: zelf.max_pad_factor.clone(),
                        plaintext } })
                .chain(self.max_pad_factor.shrink()
                    .map({ let zelf = self.clone();
                        move |max_pad_factor|
                        Self {
                            pw: zelf.pw.clone(),
                            max_pad_factor,
                            plaintext: zelf.plaintext.clone() } }))
                .chain(self.pw.shrink()
                    .map({ let zelf = self.clone();
                        move |pw|
                        Self { pw,
                            max_pad_factor: zelf.max_pad_factor.clone(),
                            plaintext: zelf.plaintext.clone() } })))
        }
    }

    #[quickcheck]
    fn enc_dec_loop(file: ScrombleFile) {
        let mut enc_file = vec![];
        scromble(Passphrase(file.pw.clone().into()), file.max_pad_factor, Box::new(&file.plaintext[..]), Box::new(&mut enc_file)).unwrap();
        let enc_file_len = enc_file.len() as f32;
        let max_pad_factor = file.max_pad_factor.unwrap_or(1.0f32);
        let enc_file_len_limit = (1f32 + max_pad_factor)*(file.plaintext.len() as f32) + (4*64 + 8) as f32;
        assert!(enc_file_len <= enc_file_len_limit,"{} <= {}",enc_file_len,enc_file_len_limit);
        let mut dec_file = vec![];
        descromble(Passphrase(file.pw.into()), Box::new(std::io::Cursor::new(&enc_file)), Box::new(&mut dec_file)).unwrap();
        assert_eq!(file.plaintext,dec_file);
    }

    #[quickcheck]
    fn decrypt_authentic(corruption_mask: (u8,Vec<u8>), corruption_pos: u16, file: ScrombleFile) {
        let mut enc_file = vec![];
        scromble(Passphrase(file.pw.clone().into()), file.max_pad_factor, Box::new(&file.plaintext[..]), Box::new(&mut enc_file)).unwrap();

        let corruption_pos = (corruption_pos as usize) % enc_file.len();
        for (i,x) in core::iter::once(corruption_mask.0).chain((corruption_mask.1).into_iter()).enumerate() {
            let ix = corruption_pos+i;
            if ix >= enc_file.len() { break; }
            enc_file[corruption_pos+i] ^= x;
        }

        let mut dec_file = vec![];
        descromble(Passphrase(file.pw.into()), Box::new(std::io::Cursor::new(&enc_file)), Box::new(&mut dec_file)).unwrap_err();
    }

    #[quickcheck]
    fn decrypt_wrong_pw(wrong_pw: String, file: ScrombleFile) {
        let mut enc_file = vec![];
        scromble(Passphrase(file.pw.clone().into()), file.max_pad_factor, Box::new(&file.plaintext[..]), Box::new(&mut enc_file)).unwrap();

        let mut dec_file = vec![];
        descromble(Passphrase(wrong_pw.into()), Box::new(std::io::Cursor::new(&enc_file)), Box::new(&mut dec_file)).unwrap_err();
    }

    // TODO: come up with better statistical tests
    #[quickcheck]
    fn encrypt_uncorrelated(file: ScrombleFile) {
        let mut enc_file1 = vec![];
        scromble(Passphrase(file.pw.clone().into()), file.max_pad_factor, Box::new(&file.plaintext[..]), Box::new(&mut enc_file1)).unwrap();
        let mut enc_file2 = vec![];
        scromble(Passphrase(file.pw.clone().into()), file.max_pad_factor, Box::new(&file.plaintext[..]), Box::new(&mut enc_file2)).unwrap();

        assert!(enc_file1.len() < u32::MAX as usize);

        let mut hist1 = [0usize; 256];
        let mut hist1_samples = 0usize;
        let mut hist2 = [0usize; 256];
        let mut hist2_samples = 0usize;
        let mut hist_diff = [0usize; 256];
        let mut hist_diff_samples = 0usize;

        for i in 0..max(enc_file1.len(),enc_file2.len()) {
            if i < enc_file1.len() {
                if i < enc_file2.len() {
                    hist_diff_samples += 1;
                    hist_diff[enc_file1[i].wrapping_sub(enc_file2[i]) as usize] += 1;
                }

                hist1_samples += 1;
                hist1[enc_file1[i] as usize] += 1;
            }

            if i < enc_file2.len() {
                hist2_samples += 1;
                hist2[enc_file2[i] as usize] += 1;
            }
        }

        let hists = vec![(hist1_samples, hist1), (hist2_samples, hist2),
            (hist_diff_samples, hist_diff)];

        for (i,(n,hist)) in hists.into_iter().enumerate() {
            assert!(n > 0);
            let mut ent = 0f64;
            for c in hist {
                let p = (c as f64)/(n as f64);
                let lg_p = p.log2();
                if lg_p.is_finite() {
                    ent += -(p*lg_p/8f64);
                }
            }

            assert!(ent > 0.85, "{}: ent = {}", i, ent);
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "scromble",
about = concat!(
"Symmetric, randomized, authenticated encryption/decryption\n\n",
"Passphrases are read from stdin (until newline or eof).\n",
"Outputs are written to stdout (non-windows only) or `outfile`.\n",
"Algorithms: argon2 (pbkdf), xchacha20 (stream cipher), blake2b (kdf,hmac).\n",
"Run with `explain-design` for more details\n\n",
)
)]
#[allow(dead_code)]
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
    ExplainDesign {},

    /// Generate a shell completion file.
    GenCompletion {
        /// Which shell to generate completions for (leave empty to list
        /// the available options)
        which_shell: Option<String>,

        /// Where to put the completions
        #[structopt(parse(from_os_str))]
        outfile: Option<PathBuf>,
    },
}

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

// #[test]
// fn all_sizes_agree() {
//     assert_eq!(blake2b_simd::OUTBYTES, chacha20::BLOCK_SIZE);
// }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Command::from_args();
    let password = Passphrase(rpassword::read_password()?.into());

    let stdout = std::io::stdout();
    let open_outfile = |outfile: _| -> Result<Box<dyn Write>, std::io::Error> {
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
            descromble(password, Box::new(File::open(&file)?), open_outfile(outfile)?)?;
        }

        _ => {
            unimplemented!();
        }
    }
    Ok(())
}
