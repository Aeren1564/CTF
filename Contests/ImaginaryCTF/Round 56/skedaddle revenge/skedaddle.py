#!/usr/local/bin/python3
def fmix128(k):
    k ^= k >> 65
    k *= 0xff51afd7ed558ccdff51afd7ed558ccd
    k &= 0xffffffffffffffffffffffffffffffff
    k ^= k >> 65
    k *= 0xc4ceb9fe1a85ec53c4ceb9fe1a85ec53
    k &= 0xffffffffffffffffffffffffffffffff
    k ^= k >> 65
    return k

k = int(input('k: '), 0)
if 0 < k < 2**128 and k == fmix128(k):
    print('ictf{REDACTED}')
else:
    print('WRONG')
