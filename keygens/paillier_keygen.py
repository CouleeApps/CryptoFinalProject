#!/usr/bin/python3

from Crypto.Util.number import *
from gmpy import *
import sys

def get_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='little')

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("ERROR: Wrong # of args\nUSAGE: paillier_keygen PUBKEYFILE PRIVKEYFILE")
        sys.exit()
    
    p = getPrime(512)
    q = getPrime(512)
    n = p*q
    phi = (p-1)*(q-1)
    g = n+1
    mu = int(invert(phi, n))

    pubkey = open(sys.argv[1], "wb")
    pubkey.write(get_bytes(n))
    pubkey.write(get_bytes(g))
    pubkey.close()

    privkey = open(sys.argv[2], "wb")
    privkey.write(get_bytes(phi))
    privkey.write(get_bytes(mu))
    privkey.close()
