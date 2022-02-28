Intended security properties
============================

- Indistinguishability from random noise (ie, IND$-CPA): An encrypted file
  is effectively indistinguishable from random noise of the same length.
    - This is achieved by having all data output by the encryption process
      be either random data or the output of a stream cipher.
- Committing authenticity: If a file successfully decrypts to a plaintext
  `PT` using some password `PW`, you can conclude that only `PW` will
  decrypt that file, that file will only decrypt to `PT`, and someone who
  knew `PW` created it.
    - This is achieved by
        (a) deriving the HMAC and encryption keys via collision-resistant
            hash functions (`argon2i` and `blake2b`)
        (b) Authenticating with an HMAC over the whole file.
    - Any violation of this property _should_ yield a collision in either
      `argon2i` or `blake2b`.
    - A related secondary property that `scromble` aims for is that it only
      outputs any data if that data can be guaranteed to come from
      the HMAC-authenticated file, even if someone changes the underlying
      file while `scromble` is reading it. This is achieved via the [HMAC
      prefix table](#hmac-prefix-table).
- Moderate length obfuscation: The exact length of the underlying file is
  difficult to tell given the length of the encrypted file.
    - This is the most dubious property, and `scromble` should not be
      relied upon if the exact size of your data is a _critical_ piece of
      information to hide.
    - Scromble randomly pads your file (up to 100% for small files, up to
      20% for large files, see [Maximum Pad Scale](#maximum-pad-scale)) but
      can be given a custom random padding range if need be.
    - This helps somewhat when you have certain very specific file sizes,
      eg:
        - 41 byte files (git branch files, a 40-byte hex string + a
          newline)
        - exact-power-of-2 files
        - 1032 byte files (on my system, many wine DLLs are this size)

The core spec
=============

Cryptographic RNG
-----------------

The cryptographic RNG used is rust's `thread_rng`
(https://docs.rs/rand/latest/rand/fn.thread_rng.html).

Notation
--------

`a||b` denotes the concatenation of byte sequences `a` and `b`.

`0^n` denotes the byte sequence consisting of `n` zero bytes.

BLAKE2b usage
-------------

`mac2b(key,data)` is the result of running BLAKE2b with personalization string
"sCrOmBlAuThEnTiC", output length 64 bytes, and key `key` on data `data`.

`key2b(key,data)` is the result of running BLAKE2b with personalization string
"sCrOmBlEnCrYpToR", output length 32 bytes, and key `key` on data `data`.

XChaCha20 usage
---------------

`xchacha20(key,nonce,data)` is the result of running XChaCha20 with 256-bit
key `key` and 192-bit nonce `nonce` on the data stream `data`.

NOTE: `xchacha20(key,nonce,xchacha20(key,nonce,data)) == data`.

Salt block
----------

The Salt block `SB` is 64 bytes of data generated from a cryptographic RNG.

Root key derivation
-------------------

The root key is derived by `RK := argon2i(password,SB)`

Nonce block and nonce
---------------------

The nonce block `NB` is 64 bytes of data generated from a cryptographic
RNG.

The first 24 bytes (ie, 192 bits) of `NB` are the nonce `NONCE`

Subkeys
-------

The HMAC key is derived by `HK := key2b(RK,"hmac")`

The encryption key is derived by `EK := key2b(RK,"encrypt")`

Plaintext
---------

The underlying file is treated as a sequence of bytes `PT` with a 64-bit
length (measured in bytes) denoted `length(PT)`. The length can be encoded
as a little-endian 8-byte sequence `le_length(PT)`.

Maximum Pad Scale
-----------------

The maximum pad scale `MAXPAD` used when encrypting can be manually set
with `--pad-factor`. If it is not manually set, it is chosen as follows:

- `1.0`, if `length(PT) <= 2048`
- `1.0 - 0.8*(length(PT)-2048)/(65536 - 2048)`,
  if `2048 < length(PT) <= 65536`
- `0.2`, if `length(PT) > 65536`

ie, `MAXPAD` starts at `1.0`, linearly goes down to `0.2` over
`[2^12,2^16]`

Pad length
----------

The pad length `PADLEN` is some uniformly randomly chosen value between `0`
and `MAXPAD*max(64,length(PT))`, ie:

- if `length(PT) < 64`, `PADLEN` is sampled from `[0,MAXPAD*64]`
- otherwise, `PADLEN` is sampled from `[0,MAXPAD*length(PT)]`

Padded Plaintext
----------------

The padded plaintext `PPT` of some plaintext data stream `PT` is:

    PPT = (PT||0^PADLEN||le_length(PT))

Where `0^PADLEN` denotes a sequence of `PADLEN` zero bytes, and .

Core Ciphertext
---------------

The core ciphertext `CC` is `NB||xchacha20(EK,NONCE,PPT)`

MAC Block
---------

The MAC block `MB` is 64 bytes of data formed by running `mac2b(HK,SB||CC)`.

Non-shared file format
----------------------

A non-shared encrypted file is `SB||CC||MB`.

Non-shared encryption procedure
===============================

Using the definitions above, encryption of a plaintext file `PT` is then:

- Read the password `password`.
- Generate `SB` and `NB`.
- Calculate the root key from `password` and `SB`.
- Calculate `HK` and `EK` from `RK`.
- Calculate `MAXPAD` from `length(PT)` and generate `PADLEN`.
- Generate the core ciphertext `CC` from this data and the plaintext `PT`.
- Calculate the MAC block `MB` from `HK` and `SB||CC`
- Output the encrypted file.

The actual implementation does this in a streaming manner.

Non-shared decryption procedure
===============================

Decryption uses most of the same building blocks as encryption, but there
are a few extra principles decryption must follow:

- Under no circumstance will we do anything with the ciphertext other than
  MAC checking before the MAC has been checked. For some reasonable
  commentary about why this is an important design principle, see [this
  blog
  post](https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html).
- No data inconsistent with the MAC will be output to stdout.
- No properties of the underlying data will be checked by `scromble`.

The second principle requires a secondary data structure I refer to as the
"HMAC prefix table". See the [HMAC prefix table](#hmac-prefix-table)
section for more details.

Using the definitions above, decryption of a ciphertext file is then:

Pass 1:

- Read the password `password`.
- Read `SB`.
- Calculate the root key from `password` and `SB`.
- Calculate `HK` from `RK`.
- Read the file as `SB||CC||MB`, build the HMAC prefix table, save the last
  8 bytes of `CC` as `enc_supposed_len`, and check that `length(CC) >= 8`
  and `MB == mac2b(HK,SB||CC)`. If either check fails, exit with an error.

From this point on, all operations involving data read from the file will
be checked against the HMAC prefix table before any further processing is
done on them. See [HMAC prefix table](#hmac-prefix-table).

Pass 2:
- Calculate `EK` from `RK`.
- Read `SB` and `NB`, and parse `NONCE` out of `NB`.
- Calculate `supposed_len` by decrypting `enc_suppposed_len` with `EK` and
  `NONCE` and interpreting it as a 64-bit little endian integer. This
  decryption takes advantage of the fact that `XChaCha20` is seekable.
- Calculate `length(PT) := min(supposed_len,length(CC)-8)`.
- Read `CC`, checking against the HMAC prefix table before doing any
  processing. If any check fails, exit with an error.
- Output the first `length(PT)` bytes of `xchacha20(EK,NONCE,CC)`.
- Finally, check that the file ends with `MB`. If not, exit with an error.

(In Progress) Secret Shared format
==================================

Secret-sharing key derivation
-----------------------------

When a file is secret-shared, share `i` has a secret-sharing key
`SSK_i := argon2i(password,NB)`

