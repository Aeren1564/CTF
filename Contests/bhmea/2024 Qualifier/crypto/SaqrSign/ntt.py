#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Qualifiers
#
# [Hard] Crypto - SaqrSign
#

# Non-native imports
from Crypto.Util.number import inverse     # pip install pycryptodome


# Math class
class NTTDomain:
    """ Class for fast polynomial arithmetic using Number Theoretic Transform over Negative-Wrapped Convolutions. """
    def __init__(self, q: int, w: int, p: int):
        self.q = q
        self.w, self.wInv = w, inverse(w, q)
        self.p, self.pInv = p, inverse(p, q)
        
    def fromPoly(self, poly):
        """ Returns NTTPoints object for a given polynomial on ZZ[x]/[x^N + 1]. """
        return NTTPoints(self, self.NTT([(j * pow(self.p, i, self.q)) % self.q for i,j in enumerate(poly)], self.w))
    
    def fromPoints(self, pts):
        """ Return NTTPoints object for given set of NTT points. """
        return NTTPoints(self, pts)

    def NTT(self, poly: list, w: int) -> list:
        """ Recursive Number Theoretic Transform (NTT) transformation. """
        ln = len(poly)
        if ln == 2:
            pts = ln*[0]
            pts[0] = (poly[0] + poly[1]) % self.q
            pts[1] = (poly[0] - poly[1]) % self.q
            return pts
        else:
            pts = ln*[0]
            k = 1
            polyEven = (ln >> 1)*[0]
            polyOdd  = (ln >> 1)*[0]
            for i in range(ln >> 1):
                polyEven[i] = poly[2 * i]
                polyOdd[i]  = poly[2 * i + 1]
            ptsEven = self.NTT(polyEven, pow(w, 2, self.q))
            ptsOdd  = self.NTT(polyOdd, pow(w, 2, self.q))
            for i in range(ln >> 1):
                pts[i]             = (ptsEven[i] + k * ptsOdd[i]) % self.q
                pts[i + (ln >> 1)] = (ptsEven[i] - k * ptsOdd[i]) % self.q
                k *= w
        return pts


class NTTPoints:
    def __init__(self, domain: NTTDomain, pts: list):
        self.domain = domain
        self.pts = pts
        
    def __repr__(self):
        pint = sum([j * self.domain.q**i for i,j in enumerate(self.pts)])
        pbyt = pint.to_bytes(-(-len(bin(pint)[2:]) // 8), 'big')
        return '{}'.format(pbyt.hex())
        
    def __add__(self, other):
        assert isinstance(other, self.__class__)
        assert all([
            len(self.pts) == len(other.pts),
            self.domain == other.domain
        ])
        return self.__class__(self.domain, [(i + j) % self.domain.q for i,j in zip(self.pts, other.pts)])
    
    def __sub__(self, other):
        assert isinstance(other, self.__class__)
        assert all([
            len(self.pts) == len(other.pts),
            self.domain == other.domain
        ])
        return self.__class__(self.domain, [(i - j) % self.domain.q for i,j in zip(self.pts, other.pts)])
    
    def __mul__(self, other):
        assert isinstance(other, NTTPoints)
        assert all([
            len(self.pts) == len(other.pts),
            self.domain == other.domain
        ])
        return self.__class__(self.domain, [(i * j) % self.domain.q for i,j in zip(self.pts, other.pts)])
    
    def inverse(self):
        return self.__class__(self.domain, [inverse(i, self.domain.q) for i in self.pts])