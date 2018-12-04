#!/usr/bin/python3

from Crypto.Util.number import *
from gmpy import *
import sys

BG_KEY_LENGTH = 128

def get_bytes(i):
    if i > 0:
        return i.to_bytes((i.bit_length() + 7) // 8, byteorder='little')
    else:
        return i.to_bytes((i.bit_length() + 7) // 8, byteorder='little', signed=True)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("ERROR: Wrong # of args\nUSAGE: bg_keygen PUBKEYFILE PRIVKEYFILE")
        sys.exit()
    
    p = 0 
    q = 0
    while ((p & 3) != 3) or ((q & 3) != 3):
        p = getPrime(8 * BG_KEY_LENGTH)
        q = getPrime(8 * BG_KEY_LENGTH)

    n = p * q

#    print(p)
#    print(q)

    pubkey = open(sys.argv[1], "wb")
    pubkey.write(get_bytes(n))
    pubkey.close()

    privkey = open(sys.argv[2], "wb")
    privkey.write(get_bytes(p))
    privkey.write(get_bytes(q))
    privkey.close()
