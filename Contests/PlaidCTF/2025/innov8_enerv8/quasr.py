se_state0, se_state1 = 13958545901828929099, 26248010522138

import struct
from math import floor
def v8ToDouble(state0):
    return (state0 >> 11) / (1 << 53)

def nodeToDouble(state0):
    kExponentBits = 0x3FF0000000000000
    random = (state0 >> 12) | kExponentBits
    packed = struct.pack('Q', random)
    unpacked = struct.unpack('d', packed)
    return unpacked[0] - 1.0

vals = []
MASK = 0xFFFFFFFFFFFFFFFF
for i in range(128):
    se_s1 = se_state0
    se_s0 = se_state1
    se_state0 = se_s0
    se_s1 ^= (se_s1 << 23) & MASK
    se_s1 ^= se_s1 >> 17
    se_s1 ^= se_s0
    se_s1 ^= se_s0 >> 26
    se_state1 = se_s1
    x = [v8ToDouble(se_state0), nodeToDouble(se_state0), se_state0]
    vals.append(x)

vals_sorted = []
for i in range(63, -1, -1):
    vals_sorted.append(vals[i])

for i in range(127, 79, -1):
    vals_sorted.append(vals[i])





f2i = lambda x, N: int(floor(x * N))

mismatched_float = 0
mismatched_int_p1 = 0
mismatched_int_m1 = 0
for i in range(len(vals_sorted)):
    if vals_sorted[i][0] != vals_sorted[i][1]:
        mismatched_float += 1
    if f2i(vals_sorted[i][0], (1 << 52) + 1) != f2i(vals_sorted[i][1], (1 << 52) + 1):
        mismatched_int_p1 += 1
    if f2i(vals_sorted[i][0], (1 << 52) - 1) != f2i(vals_sorted[i][1], (1 << 52) - 1):
        mismatched_int_m1 += 1
    
print("mismatched_float:", mismatched_float)
print("mismatched_int_p1:", mismatched_int_p1)
print("mismatched_int_m1:", mismatched_int_m1)