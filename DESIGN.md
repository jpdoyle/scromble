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
    - When decrypting, scromble doesn't output the padding data, so an
      adversary can observe how big the file if you let them observe the
      time or file system traffic totals of decryption. This kind of
      problem is basically unavoidable without implementing Oblivious RAM.
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

HMAC prefix table
=================

Once `scromble` has read the file and checked its HMAC, it must read
through the file a second time in order to actually decrypt the file.

However, this leads to a potential issue: what if the file changes between
the HMAC check and when scromble reads some particular piece of the file?
Then, potentially arbitrary data will get through, even though the user
believes the data has been certified as authentic.

This does not seem like an easily exploitable flaw, but who knows what
crazy situation someone might be using this tool in? It's better to build a
tool with rock solid correctness properties than to brush a clear issue
aside with "that seems too hard to exploit".

`scromble` builds an in-memory data structure during its first pass so that
every data read on the second pass can be checked for authenticity, at the
cost of some extra memory usage (at most `sqrt(N)*17` bytes of memory
usage for an N-byte file).

The HMAC prefix table consists of a block size `block_size` and a sequence
of "prefix HMACs" `hmac_prefs`. For each `i`, `hmac_prefs[i] ==
mac2b(HK,data[..(i*block_size)])`. During the HMAC-check pass, the current
HMAC result will be inserted at the end of `hmac_prefs` every `block_size`
bytes. During the decryption pass, data is buffered until `block_size`
bytes have been processed and the HMAC prefix containing those bytes is
checked.

To minimize the total memory overhead from the HMAC prefix table and the
buffer required to check against it, `chunk_size` gets updated
incrementally during the HMAC-check pass. If `hmac_prefs.len()*HMAC_LEN >=
2*block_size` (here `HMAC_LEN == 64`), then `block_size` gets updated to
`block_size*2` and every even entry in `hmac_prefs` gets deleted -- ie:

    new_block_size == block_size*2;
    new_hmac_prefs.len() == hmac_prefs.len()/2;
    for each i such that 0 <= i and 2*i+1 < hmac_prefs.len():
        new_hmac_prefs[i] == hmac_prefs[2*i+1];

This scheme approximates the memory-usage optimal HMAC prefix table size,
which is the solution to `(file_size/block_size)*HMAC_LEN == block_size` --
ie, `block_size == sqrt(file_size*HMAC_LEN)`. The computational cost
required to double the block size is `O(1)` amortized (ie, every `2^n`th
step requires an extra `O(2^n)` work), and the worst-case memory required
is `block_size + (file_size/block_size)*HMAC_LEN`. The memory usage is
highest when

    block_size + (file_size/block_size)*HMAC_LEN
    == 2*block_size + (file_size/(2*block_size))*HMAC_LEN

i.e.,

    block_size*block_size == 32*file_size
    block_size == 4*sqrt(2)*sqrt(file_size)

    total_mem <= block_size + (file_size/block_size)*HMAC_LEN
    total_mem <= block_size + 2*block_size
    total_mem <= 3*4*sqrt(2)*sqrt(file_size)
    total_mem <= (12*sqrt(2))*sqrt(file_size)

Running some numbers, this means that for this data structure, decrypting
a:

- 1 mebibyte file requires <=17KiB  of memory
- 1 gibibyte file requires <=544KiB of memory
- 1 tebibyte file requires <=16MiB  of memory
- 1 pebibyte file requires <=544MiB of memory
- 1 exbibyte file requires <=17GiB  of memory

Which seems like pretty reasonable memory overhead to me.

NOTE: for speed, `scromble` double-buffers the HMAC prefix table's read
buffer, so the actual memory usage is more like `4*block_size`, ie,
`(4/3)*total_mem`. So if you want to decrypt a 1 exbibyte file, you'll need
to use a computer with ~23GiB of memory.

(In Progress) Secret Shared format
==================================

Secret-sharing key derivation
-----------------------------

When a file is secret-shared, share `i` has a secret-sharing key
`SSK_i := argon2i(password,NB)`

