Authors: Max Thomas, Glenn Smith, Billy Zhang

12/2/2018

-----------------------------------------------------

Build with: make

The C++ executables depend on GMP, and the Python keygen
scripts depend on gmpy and pycrypto

-----------------------------------------------------

This README is provided solely to explain program operation, and should not
be considered part of the formal writeup

The server expects key files in its working directory. For it to run correctly,
at least one of the following pairs of files must be present:
"rsapubkey", "rsaprivkey"
"bgpubkey", "bgprivkey"
"papubkey", "paprivkey"

Note that the file names must match these names EXACTLY, or the server will not run.

Key generation scripts can be found in keygens/

The client's second command-line parameter is an encryption selector, where
0=RSA, 1=Blum-Goldwasser, and 2=Paillier
Note that the server must be provided with appropriate keys for any of the
algorithms to work.

This program will only run on *NIX operating systems. Specifically, it depends on
Unix syscalls for networking and makes use of /dev/urandom for session key
generation.
