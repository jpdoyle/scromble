![have your datums been scrombled?](./scrombled-edit.png)

`scromble`, a simple authenticated file encryptor.
==================================================

Have you ever wanted to encrypt *one* file with symmetric encryption?

Have you ever wanted that encryption to be randomized?

Have you ever wanted that file to be indistinguishable from random
noise?

Have you ever wanted that encryption to be authenticated?

Well, I certainly did! And apparently no existing tool did all those
things. So I made one.

Building
========

Running `nix-shell --command 'cargo build --release'` should work. The
executable will then be in `./target/release/scromble`. Please file an
issue if that doesn't work!

If you would like to use the AVX2 backend for XChaCha20, build with
`nix-shell --command 'RUSTFLAGS="-Ctarget-cpu=haswell
-Ctarget-feature=+sse2" cargo build --release'` instead. Everything
else should be the same.

Example usage
=============

    $ scromble -h
    $ echo mypassword | scromble encrypt mydata.txt >mydata.enc1
    $ echo mypassword | scromble encrypt mydata.txt >mydata.enc2
    $ echo mypassword | scromble decrypt mydata.enc1 >mydata1.txt
    $ echo mypassword | scromble decrypt mydata.enc2 >mydata2.txt
    # should be empty
    $ diff mydata{,1}.txt
    $ diff mydata{,2}.txt
    # should be different
    $ diff -b mydata.enc*
    # should fail, leaving mydata3.txt empty
    $ echo notmypassword | scromble decrypt mydata.enc2 >mydata3.txt
    Error: BadHmac

What cryptography does this use?
================================

NOTE: if any of the below information seems wrong, please file an
issue!

There are two formats, "hip and modern" and "legacy". "hip and modern" is
the default, and "legacy" only supports decryption.

Random byte generation is done with Rust's `thread_rng()`, which is a
CSPRNG (right now, I believe it's ChaCha20).

Key derivation is done by running `argon2i` on the input password,
mixed with a 64-byte salt.

Encryption is done with `XChaCha20`, with a 24 byte (192bit) nonce. In
"legacy" mode a hack is used when the keystream becomes very large:

- If the keystream extends to `core::u32::MAX/2` (ie, `2^31`, about
  128gb), it generates a key and a nonce from the keystream, and uses
  those to reinitialize XChaCha20. This can happen an unlimited number
  of times.

MAC is done with 64-byte-output `blake2b`, personalized with
`b"sCrOmBlEnCrYpToR"`. Its key is generated from the first 32 bytes of
the XChaCha20 keystream.

In both "hip and modern" mode and "legacy" mode, the MAC input starts with
all non-final blocks as they appear in the file (ie, all blocks as
described in the next section except `[HMAC]`).

In "legacy" mode, the MAC input ends there.

In "hip and modern" mode, one block of stream-encrypted `0`s is appended to
the MAC input. This prevents data corruption that if the stream cipher is
changed in a way that would generate the same HMAC key with an
eventually-different overall keystream. The primary purpose is to ensure
that "legacy" files which might be incorrectly decrypted will instead fail
the HMAC check.

What do encrypted files look like?
==================================

Encrypted files are in 64-byte blocks (notated as `[...]`). `|` means
concatenation.

Header:

    [salt]|[nonce|random_bytes]

Body:

    [ciphertext]...

Footer:

    [last_ciphertext|random_bytes]|[64-len(last_ciphertext)|random_bytes]|[HMAC]

`random_bytes` are taken from the `XChaCha20` keystream to pad blocks
to a multiple of 64 bytes.

Is this fast?
=============

On my machine I'm seeing encryption and decryption speeds of
150-180MB/s (default `sse2` backend) and 200-240MB/s (`avx2` backend)
when measured through `iotop` -- although, decryption will require
reading the whole file twice. It can probably be made faster, either
through simple optimizations or by multithreading it.

Is this reliable?
=================

I made this in a day and it hasn't been independently audited (yet).
It is built using fairly reputable Rust-based implementations of the
involved cryptographic primitives, and it is simple enough that there
shouldn't be many subtle ways for it to be implemented incorrectly. I
am willing to use it for my own needs, but as they say:

```
  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
```

