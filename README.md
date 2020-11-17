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



