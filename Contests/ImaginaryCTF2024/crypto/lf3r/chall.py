import secrets, os

n = 256
MASK = 0x560074275752B31E43E64E99D996BC7B5A8A3DAC8B472FE3B83E6C6DDB5A26E7
# n = 8
# MASK = 0b01100101

# hidden
flag = "ictf{S0me_T3st_Fl4g}".encode()

class LF3R:
    def __init__(self, n, key, mask):
        self.n = n
        self.state = key & ((1 << n) - 1)
        self.mask = mask

    def __call__(self):
        v = self.state % 3
        self.state = (self.state >> 1) | (
            (bin(self.state & self.mask).count('1') & 1) << (self.n - 1)
        )
        return v


def int_to_base(n, b):
    digits = []
    while n:
        digits.append(n % b)
        n //= b
    return digits


if __name__ == "__main__":
    #key = secrets.randbits(n)
    key = 69408557081905889783115087534696383805401368110697105231628361605670518149690
    lf3r = LF3R(n, key, MASK)

    stream = [lf3r() for _ in range(2048)]

    flag_digits = int_to_base(int.from_bytes(flag, "big"), 3)
    stream += [(x + lf3r()) % 3 for x in flag_digits]
    print(f"{n = }")
    print(f"{MASK = }")
    print(f"{stream = }")
