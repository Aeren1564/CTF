import ec
import hashlib
import random

class ECDSA(ec.ECC):
    def __init__(self, c):
        super().__init__(c)

    def hash(self, m):
        return int.from_bytes(hashlib.sha256(m).digest())

    def sign(self, m):
        e = self.hash(m)
        z = e & ((1 << self.c.l) - 1)
        while True:
            k = random.randint(1, self.c.n - 1)
            p = k * self.c.g
            r = p.x % self.c.n
            if r == 0:
                continue
            s = pow(k, -1, self.c.n) * (z + r * self.key) % self.c.n
            if s != 0:
                break
        return (r, s)

    def verify(self, m, sig):
        r, s = sig
        if not (1 <= r < self.c.n and 1 <= s < self.c.n):
            return False
        e = self.hash(m)
        z = e & ((1 << self.c.l) - 1)
        w = pow(s, -1, self.c.n)
        u1 = (z * w) % self.c.n
        u2 = (r * w) % self.c.n
        p = u1 * self.c.g + u2 * self.pkey
        if p == self.c.inf:
            return False
        return p.x % self.c.n == r
