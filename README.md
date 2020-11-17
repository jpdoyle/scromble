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

Random byte generation is done with Rust's `thread_rng()`, which is a
CSPRNG (right now, I believe it's ChaCha20).

Key derivation is done by running `argon2i` on the input password,
mixed with a 64-byte salt.

Encryption is done with `XChaCha20`, with a 24 byte (192bit) nonce.

MAC is done with 64-byte-output `blake2b`, personalized with
`b"sCrOmBlEnCrYpToR"`. Its key is generated from the first 32 bytes of
the XChaCha20 keystream.

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

On my machine I'm seeing encryption speeds of 60MB/s and decryption
speeds of 50MB/s (decryption requires reading the whole file twice).
It can probably be made faster, either through simple optimizations or
by multithreading it.

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

