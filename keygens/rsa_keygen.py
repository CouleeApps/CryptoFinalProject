#!/usr/bin/python3

from Crypto.Util.number import *
from gmpy import *
import sys, random

keysize = 128

def get_bytes(i):
    bts = i.to_bytes((i.bit_length() + 7) // 8, byteorder='little')
    bts += bytes(1) * (keysize - len(bts))
    return bts

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("ERROR: Wrong # of args\nUSAGE: rsa_keygen PUBKEYFILE PRIVKEYFILE")
        sys.exit()

    p = getPrime(4*keysize)
    q = getPrime(4*keysize)
    n = p*q
    phi = (p-1)*(q-1)
    e = 65537
    d = int(invert(e, phi))

    pubkey = open(sys.argv[1], "wb")
    pubkey.write(get_bytes(n))
    pubkey.write(get_bytes(e))
    pubkey.close()

    privkey = open(sys.argv[2], "wb")
    privkey.write(get_bytes(d))
    privkey.close()
