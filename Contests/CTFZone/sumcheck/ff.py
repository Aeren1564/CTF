#!/usr/bin/python3
try:
    from gmpy2 import mpz
except ImportError:
    print("Won't use gmpy2, will be slower")

    def mpz(x):
        return x


from Crypto.Util.number import long_to_bytes, bytes_to_long

import unittest

alt_bn128_p = (
    21888242871839275222246405745257275088696311157297823662689037894645226208583
)

alt_bn128_r = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)


FF_BYTE_LENGTH = 32


class FF:
    value = mpz(0)
    modulus = mpz(1)

    def __init__(self, x, m) -> None:
        if type(x) == FF:
            self.modulus = x.modulus
            self.value = x.value
        else:
            self.modulus = mpz(m)
            self.value = mpz(x) % self.modulus
        pass

    def __eq__(self, value: object) -> bool:
        if type(value) == int:
            return self == type(self)(value)
        assert self.modulus == value.modulus
        return self.value == value.value

    def __add__(self, value: object) -> object:
        assert self.modulus == value.modulus
        if type(self) == FF:
            return type(self)((self.value + value.value) % self.modulus, self.modulus)
        else:
            return type(self)((self.value + value.value) % self.modulus)

    def __sub__(self, value: object) -> object:
        assert self.modulus == value.modulus
        return type(self)((self.value - value.value) % self.modulus, self.modulus)

    def __mul__(self, value: object) -> object:
        assert self.modulus == value.modulus
        if type(self) == FF:
            return type(self)((self.value * value.value) % self.modulus, self.modulus)
        else:
            return type(self)((self.value * value.value) % self.modulus)

    def pow(self, power):
        power = power % (self.modulus - 1)
        result = FF(1, self.modulus)
        running_square = FF(self.value, self.modulus)
        for i in range(0, self.modulus.bit_length()):
            if power & 1:
                result *= running_square
            running_square *= running_square
            power = power >> 1
        return result

    def invert(self):
        return self.pow(self.modulus - 2)

    def __div__(self, value: object) -> object:
        assert self.modulus == value.modulus
        return self * value.invert()

    def __truediv__(self, value: object) -> object:
        assert self.modulus == value.modulus
        return self * value.invert()

    def __neg__(self) -> object:
        return self.__class__((self.modulus - self.value) % self.modulus, self.modulus)

    def __str__(self) -> str:
        return "FF(" + str(self.value) + ")"

    def __hash__(self) -> int:
        return self.value

    def __repr__(self):
        return self.__str__()

    def to_bytes(self):
        return long_to_bytes(self.value, FF_BYTE_LENGTH)


class Fr(FF):
    def __init__(self, x, m=alt_bn128_r):
        assert m == alt_bn128_r
        if type(x) == Fr:
            FF.__init__(self, x.value, alt_bn128_r)
        else:
            FF.__init__(self, x, alt_bn128_r)

    def __str__(self) -> str:
        return "Fr(" + str(self.value) + ")"

    @staticmethod
    def from_bytes(data):
        assert len(data) >= FF_BYTE_LENGTH
        return Fr(bytes_to_long(data))


class Fq(FF):
    def __init__(self, x):
        FF.__init__(self, x, alt_bn128_p)

    def __str__(self) -> str:
        return "Fq(" + str(self.value) + ")"

    @staticmethod
    def from_bytes(data):
        assert len(data) >= FF_BYTE_LENGTH
        return Fq(bytes_to_long(data))


class TestFFMethods(unittest.TestCase):
    def test_add(self):
        a = FF(3, 4)
        b = FF(2, 4)
        self.assertTrue((a + b).value == 1)

    def test_sub(self):
        a = Fr(0)
        b = Fr(1)
        self.assertTrue((a - b).value == alt_bn128_r - 1)

    def test_mul_div(self):
        a = Fr(2)
        b = a.invert()
        c = a * b
        self.assertTrue(c.value == 1)


if __name__ == "__main__":
    unittest.main()
