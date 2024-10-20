from .const import (
    Masks,
    RotationConstants,
    RoundConstants
)
from .. import RandomNumberGenerator

from functools import reduce
from operator import xor
from copy import deepcopy

def rol(value, left, bits):
    top = value >> (bits - left)
    bot = (value & Masks[bits - left]) << left
    return bot | top

def padding(used_bytes, align_bytes):
    padlen = - used_bytes % align_bytes
    if padlen == 0:
        padlen = align_bytes
    if padlen == 1:
        return [0x81]
    else:
        return [0x01] + ([0x00] * (padlen - 2)) + [0x80]


class Keccak:

    def __init__(self, bitrate = 1088, b = 1600):
        self.bitrate = bitrate
        self.b = b
        
        # only byte-aligned
        assert self.bitrate % 8 == 0
        self.bitrate_bytes = self.bitrate // 8
        
        assert self.b % 25 == 0
        self.lanew = self.b // 25
        
        self.s = [[0] * 5 for _ in range(5)]
    
    def _theta(self):
        C = [reduce(xor, self.s[col]) for col in range(5)]
        for x in range(5):
            Dx = C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1, self.lanew)
            for y in range(5):
                self.s[x][y] ^= Dx

    def _rho(self):
        for x in range(5):
            for y in range(5):
                self.s[x][y] = rol(self.s[x][y], RotationConstants[y][x], self.lanew)

    def _pi(self):
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y % 5][(2 * x + 3 * y) % 5] = self.s[x][y]
        self.s = B
                
    def _chi(self):
        A = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] = self.s[x][y] ^ ((~self.s[(x + 1) % 5][y]) & self.s[(x + 2) % 5][y])
        self.s = A
        
    def _iota(self, rc):
        self.s[0][0] ^= rc

    def f(self):
        for rc in RoundConstants:
            self._theta()
            self._rho()
            self._pi()
            self._chi()
            self._iota(rc)

    def _absorb(self, bb):
        assert len(bb) == self.bitrate_bytes
        
        bb += [0] * ((self.b - self.bitrate + 7) // 8)
        i = 0
        
        for y in range(5):
            for x in range(5):
                self.s[x][y] ^= int.from_bytes(bb[i:i + 8], 'little')
                i += 8
        self.f()

    def absorb(self, data):
        data = list(data)
        data += padding(len(data), self.bitrate_bytes)
        assert len(data) % self.bitrate_bytes == 0
        for i in range(len(data) // self.bitrate_bytes):
            self._absorb(data[self.bitrate_bytes * i: self.bitrate_bytes * (i+1)])
    
    def squeeze(self):
        return self.get_bytes()[:(self.b - self.bitrate) // 16]
    
    def get_bytes(self):
        out = [0] * ((self.b + 7) // 8)
        i = 0
        for y in range(5):
            for x in range(5):
                    v = self.s[x][y].to_bytes(self.lanew // 8, 'little')
                    out[i:i+8] = v
                    i += 8
        return bytes(out)

    def get_integer(self):
        return int.from_bytes(self.get_bytes())

    def get_rng(self):
        return RandomNumberGenerator(self.get_integer())

