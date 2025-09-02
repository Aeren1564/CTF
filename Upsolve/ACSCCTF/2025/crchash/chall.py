from os import urandom
from signal import alarm
import sys

from secret import flag, p

LIMIT = 16
MASK = 0xFFFFFFFF_FFFFFFFF


def crchash(data, crc_base=0):
    crc = crc_base
    for byte in data:
        crc ^= byte << (64 - 8)
        for _ in range(8):
            if crc & (1 << 63):
                crc = (crc << 1) ^ p
            else:
                crc <<= 1
    return crc & MASK


if __name__ == "__main__":
    alarm(10)

    m = urandom(LIMIT)
    h = crchash(m)

    sys.stdout.write(str(int.from_bytes(m, byteorder="big")) + "\n")
    sys.stdout.write(str(h) + "\n")
    sys.stdout.flush()

    cands = set(
        [
            (int(sys.stdin.readline().strip()) & MASK).to_bytes(8, byteorder="big")
            for _ in range(16)
        ]
    )
    assert len(cands) == 16
    assert len(set(map(crchash, cands)) | {h}) == 1

    sys.stdout.write(flag + "\n")
    sys.stdout.flush()
