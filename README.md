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
else should be the same. The fastest results I've seen are expected
with `RUSTFLAGS="-Ctarget-cpu=native"`.

NOTE FOR WINDOWS USERS
======================

`scromble` was designed and tested on Linux, so writing the output to
`stdout` was a perfectly reasonable, sensible idea. However,
apparently on Windows, writing non-unicode data to `stdout` crashes
the program, and if you redirect `stdout` to a file causes bytes to be
interpreted as UTF-8, then converted to UTF-16le with a byte order
marker and some extra data. I'm working on understanding how on earth
to deal with that, but for now, please use
`scromble encrypt <infile> <outfile>`
and `scromble decrypt <infile> <outfile>`.

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
    Error: Ciphertext has an incorrect HMAC

What cryptography does this use?
================================

For detailed information on the overall design, please see `DESIGN.md` or
run `scromble explain-design`.

Is this fast?
=============

On my machine I'm seeing encryption and decryption speeds of
150-180MB/s (default `sse2` backend) and 200-240MB/s (`avx2` backend)
when measured through `iotop` -- although, decryption will require
reading the whole file twice. With `RUSTFLAGS="-Ctarget-cpu=native"`,
I observed ~300-330MB/s.  It can probably be made faster, either
through simple optimizations or by multithreading it.

Is this reliable?
=================

I originally made this in a day and it hasn't been independently audited
(yet). It is built using fairly reputable Rust-based implementations of the
involved cryptographic primitives, and it is simple enough that there
shouldn't be many subtle ways for it to be implemented incorrectly. I am
willing to use it for my own needs, but as they say:

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

