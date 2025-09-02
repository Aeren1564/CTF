import secrets

class EC:
    def __init__(self, p, g, a, b, n):
        self.p = p
        self.a = a
        self.b = b
        self.n = n
        self.l = self.n.bit_length()
        self.inf = Point(self, None, None)
        self.g = Point(self, *g)

    def on(self, pt):
        return pt == self.inf or (pt.y ** 2 - (pt.x ** 3 + self.a * pt.x + self.b)) % self.p == 0

class Point:
    def __init__(self, c, x, y):
        self.c = c
        self.x = x
        self.y = y
        assert (x is None and y is None) or self.c.on(self)

    def copy(self):
        return Point(self.c, self.x, self.y)

    def __eq__(self, other):
        return self.c == other.c and self.x == other.x and self.y == other.y

    def __neg__(self):
        return Point(self.c, self.x, -self.y % self.c.p) if self != self.c.inf else self.copy()

    def __add__(self, other):
        assert self.c == other.c
        if self == self.c.inf:
            return other.copy()
        if other == self.c.inf:
            return self.copy()
        if self.x == other.x and self.y != other.y:
            return self.c.inf.copy()
        if self == other:
            if self.y == 0:
                return self.c.inf.copy()
            dx = 3 * self.x ** 2 + self.c.a
            dy = 2 * self.y
        else:
            dx = other.y - self.y
            dy = other.x - self.x
        s = (dx * pow(dy, -1, self.c.p)) % self.c.p
        nx = (s ** 2 - self.x - other.x) % self.c.p
        ny = (s * (self.x - nx) - self.y) % self.c.p
        return Point(self.c, nx, ny)

    def __rmul__(self, k):
        k %= self.c.n
        r = self.c.inf
        a = self
        while k > 0:
            if k & 1:
                r = r + a
            a = a + a
            k >>= 1
        return r

    def __str__(self):
        return f'({self.x}, {self.y})'

    def __repr__(self):
        return str(self)

class secp256k1(EC):
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
    A = 0
    B = 7
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    def __init__(self):
        super().__init__(self.P, self.G, self.A, self.B, self.N)

class ECC:
    def __init__(self, c):
        self.c = c
        self.key = secrets.randbelow(self.c.n - 1) + 1
        self.pkey = self.key * self.c.g

    @property
    def compressed_pubkey(self):
        return '0x' + ('03' if self.pkey.y & 1 else '02') + hex(self.pkey.x)[2:]
