#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Qualifiers
#
# [Hard] Crypto - SaqrSign
#

# Native imports
import os, hashlib, json
from secrets import randbelow

# Non-native imports
from Crypto.Util.number import inverse, isPrime     # pip install pycryptodome

# Local imports
from ntt import NTTDomain, NTTPoints

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c796d65726f5761734865726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Crypto class
class SaqrSign:
    """ Class for signing and verifying SaqrSign signatures. """
    def __init__(self, n, q, w, p):
        # Parameter validation
        assert isPrime(q)
        assert (q - 1) % n == 0
        assert pow(w, n, q) == 1
        assert not (1 in [pow(w, i, q) for i in range(2, n)])
        assert pow(p, 2, q) == w
        assert pow(p, n, q) == q - 1
        # Set parameters
        self.n = n
        self.q = q
        # Set NTT domain
        self.ntt = NTTDomain(q, w, p)
        # Private key generation
        while True:
            G = self.ntt.fromPoly(self.GenUniformSmall(1))
            if not (0 in G.pts):
                break
        D = self.ntt.fromPoly(self.GenUniformSmall(1))
        # Public key generation
        A = self.ntt.fromPoly(self.GenUniform())
        E = (A + D) * G.inverse()
        # Set keys
        self.public = {
            'A' : A,
            'E' : E
        }
        self.private = {
            'G' : G,
            'D' : D
        }
        
    def GenUniform(self) -> list:
        """ Generates uniformly random polynomials. """
        return [randbelow(self.q) for _ in range(self.n)]

    def GenUniformSmall(self, eta: int) -> list:
        """ Generates uniformly random polynomials with (small) bounded coefficients. """
        return [(randbelow(2*eta + 1) - eta) % self.q for _ in range(self.n)]

    def HashBall(self, m: bytes, tau: int) -> list:
        """ Deterministically generates sparse polynomials with weight tau. """
        if isinstance(m, str):
            m = m.encode()
        h = hashlib.sha256(m).digest()
        c = self.n * [0]
        for i in range(self.n - tau, self.n):
            hi = int(hashlib.sha256(h + i.to_bytes(2, 'big')).hexdigest(), 16)
            hi //= i; j = hi % i; hi //= i
            hi //= 2; k = hi % 2; hi //= 2
            c[i] = c[j]
            c[j] = (1 - 2 * k) % self.q
        return c
    
    def Sign(self, m: bytes) -> tuple:
        """ Signs a message. """
        if isinstance(m, str):
            m = m.encode()
        Y1 = self.ntt.fromPoly(self.HashBall(os.urandom(32), 140))
        Y2 = self.ntt.fromPoly(self.GenUniformSmall(64))
        P = self.public['A'] * Y1 + Y2
        r = hashlib.sha256(str(P).encode()).digest()
        C = self.ntt.fromPoly(self.HashBall(m + r, 38))
        U = Y1 + C
        V = self.private['G'] * U
        W = Y2 - self.private['D'] * U
        return r.hex(), V, W

    def Verify(self, m: bytes, sig: tuple) -> bool:
        """ Verifies a signature. """
        if isinstance(m, str):
            m = m.encode()
        r, V, W = sig
        if isinstance(r, str):
            r = bytes.fromhex(r)
        C = self.ntt.fromPoly(self.HashBall(m + r, 38))
        Z = self.public['E'] * V - self.public['A'] * C + W
        return r == hashlib.sha256(str(Z).encode()).digest()


# Challenge parameters
N, Q, W, P = 1024, 12289, 4324, 9389

# Challenge set-up
HDR = r"""|
|     ( \                   ( \  (_)
|      \ \   ____  ____  ____\ \  _  ____ ____
|       \ \ / _  |/ _  |/ ___)\ \| |/ _  |  _ \
|   _____) | ( | | | | | |_____) ) ( ( | | | | |
|  (______/ \_||_|\_|| |________/|_|\_|| |_| |_|
|                    |_|           (_____|"""
print(HDR)

saqr = SaqrSign(N, Q, W, P)

assert saqr.Verify(FLAG, saqr.Sign(FLAG))

print('|\n|  Public = {}'.format(json.dumps({
    'A' : str(saqr.public['A']), 
    'E' : str(saqr.public['E'])
})))


# Server loop
TUI = "|\n|  Menu:\n|    [S]ign\n|    [C]ompare Ds\n|    [Q]uit\n|"

while True:
    try:

        print(TUI)
        choice = input("|  > ").lower()

        if choice == 'q':
            print('|\n|  [~] Goodbye ~ !\n|')
            break
        
        elif choice == 's':
            uin = input("|  > (str) ")
            sig = saqr.Sign(uin)
            print('|  Sig = {}'.format(json.dumps({
                'r' : sig[0],
                'V' : str(sig[1]),
                'W' : str(sig[2])
            })))

        elif choice == 'c':
            uin = input("|  > (hex) ")
            if uin == str(saqr.private['D']):
                print('|\n|\n|  Flag = {}\n|\n|  Good job ~ !...\n|'.format(FLAG.decode()))
                break
            else:
                print('|  [!] Wrong D...')

        else:
            print('|  [!] Invalid choice.')

    except KeyboardInterrupt:
        print('\n|\n|  [~] Goodbye ~ !\n|')
        break

    except Exception as e:
        print('|  [!] ERROR :: {}'.format(e))