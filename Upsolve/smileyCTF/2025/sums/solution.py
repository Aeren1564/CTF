from pwnlib.tubes.remote import remote
from pwnlib.tubes.process import process
import ast
from polynomial import MVLinear
p = 2**256 - 189


def untamper(num):
        """
        untamper a `num` to give back the internal state register
        """
        def get_bit(number, position):
            if position < 0 or position > 32 - 1:
                return 0
            return (number >> (32 - 1 - position)) & 1

        def set_bit_to_one(number, position):
            return number | (1 << (32 - 1 - position))

        def undo_right_shift_xor_and(result, shift_len, andd=-1):
            original = 0
            for i in range(32):
                if get_bit(result, i) ^ \
                   (get_bit(original, i - shift_len) &
                        get_bit(andd, i)):
                    original = set_bit_to_one(original, i)
            return original

        def undo_left_shift_xor_and(result, shift_len, andd):
            original = 0
            for i in range(32):
                if get_bit(result, 32 - 1 - i) ^ \
                   (get_bit(original, 32 - 1 - (i - shift_len)) &
                        get_bit(andd, 32 - 1 - i)):
                    original = set_bit_to_one(original, 32 - 1 - i)
            return original
        num = undo_right_shift_xor_and(num, 18)
        num = undo_left_shift_xor_and(num, 15, 0xEFC60000)
        num = undo_left_shift_xor_and(num, 7, 0x9D2C5680)
        num = undo_right_shift_xor_and(num, 11, 0xFFFFFFFF)
        return num

def tamper(num):
    """
    extract tampered state at internal index i
    if index reaches end of state array, twist and set it to 0
    """
    num = num ^ ((num >> 11) & 0xFFFFFFFF)
    num = num ^ ((num << 7) & 0x9D2C5680)
    num = num ^ ((num << 15) & 0xEFC60000)
    num = num ^ (num >> 18)
    return num & ((1 << 32) - 1)


def read_poly(io):
    data = io.recvline().decode().strip().split("al: ")[-1]
    data = ast.literal_eval(data)
    return data

def get_rs(io, expect = 1337, is_final = False):
    rs = []
    p0, p1 = 1, expect - 1
    io.sendlineafter(b': ', str(expect).encode())
    io.sendlineafter(b': ', str(p0).encode())
    io.sendlineafter(b': ', str(p1).encode())

    io.recvline()
    io.sendlineafter(b': ', b'y')
    for _ in range(9):
        challenge = io.recvline().decode().strip().split(': ')[-1]
        r = ast.literal_eval(challenge)[1]
        rs.append(r)
        expect = (p0 + r * (p1 - p0)) % p
        if is_final and _ == 8:
            return expect, rs
        p0 = 1
        p1 = expect - 1
        io.sendlineafter(b': ', str(p0).encode())
        io.sendlineafter(b': ', str(p1).encode())
    # print(f'{rs = }')
    io.recvlines(3)
    return rs
    # print(len(rs))
    # poly_r = MVLinear(10, poly_terms, p)
    # print()
    # print(poly_r.eval(rs))
    # io.interactive()
    # exit()
def skip_states(io, count = 2):
    payload = b'1337\n1336\n1\nn\n' * count
    io.send(payload)
    tmp = io.recvlines(count * 5)
    # tmp = [tmp[i] for i in range(len(tmp)) if i % 5 != 0]
    # print(tmp)
    # print(tmp[1:4] + tmp[5:])
def skip_state(io):
    io.sendlineafter(b': ', b'1337')
    io.sendlineafter(b': ', b'0')
    io.sendlineafter(b': ', b'1')
    # print(io.recvline())
    print(io.recvlines(3))

def get_next_state(s0, s1, s397):
    x = (s0 & 0x80000000) + (s1 & 0x7FFFFFFF)
    xA = x >> 1
    if (x % 2) != 0:
        xA = xA ^ 0x9908B0DF
    res = s397 ^ xA
    return res
REMOTE = True
if REMOTE:
    io = remote("smiley.cat", 44873)
else:
    io = process(["python", "sums.py"])

# for _ in range(3):
rs = []
idx = 0

skip_states(io, 2) # Skip state 0 -> 7, current state: 8
print('Skipping state 0 - > 15, StateIDX = 16') # Current state: 8
# exit()
_ = read_poly(io)
rs += get_rs(io)
print('Getting state 16 - > 87, StateIDX = 96') # Current state: 88

# for i in range(10):
#     print(f'{i = }')
#     skip_states(io, 4) # Skip state 88 - > 407, current state: 408
print('Skipping state 96 -> 415') # Current state: 408

_ = read_poly(io)
rs += get_rs(io)
print('Getting state 416 -> 487') # Current state: 488

for i in range(4):
    print(f'{i = }')
    skip_states(io, 4)
print('Skipping state 506 -> 623') # Current state: 400

poly = MVLinear(10, read_poly(io), p)
expect, last_rs = get_rs(io, expect=1337, is_final=True)
print(len(rs))
states = []
mask = (1 << 32) - 1
for r in rs:
    while r != 0:
        states.append(untamper(r & mask))
        r >>= 32
# 8 -> 79, 408 -> 479
# states = [untamper(x) for x in states]

for i in range(8, len(states) // 2 - 16, 8):
    s0, s1, s397 = states[i], states[i + 1], states[i + 69]
    lhs = tamper(get_next_state(s0, s1, s397))
    t = last_rs[i // 8 + 1] & mask
    print(f'{t = }\n{lhs = }\n{i = }')

target_r = 0
M = 2** 32
for i in range(56, 64):
    s0, s1, s397 = states[i], states[i + 1], states[i + 69]
    target_r += tamper(get_next_state(s0, s1, s397)) * M**(i - 56)
# target_r = int(bin(target_r)[2:].zfill(256)[::-1], 2)
points = last_rs + [target_r]
print(f'{points = }')
final_sum = poly.eval(points)
print(f'{final_sum = }')
p0 = (final_sum - target_r * expect) * pow(1 - 2 * target_r, -1, p) % p
p1 = (expect - p0) % p
print((p0 + p1) % p == expect)
print((p0 + target_r * (p1 - p0)) % p == final_sum)
io.sendlineafter(b': ', str(p0).encode())
io.sendlineafter(b': ', str(p1).encode())
io.interactive()
# print(f'{target_r = }')
# print([x & mask for x in target_rs])
# print(tamper(get_next_state(s0, s1, s397)))
# print(len(states))
# s0, s1, s397 = states[0], states[1], states[396]
# exit()
# 
# for idx in range(0, max(target_idx) + 1, 8):
#     poly = read_poly(io)
#     if idx not in [0, 392]:
#         skip_state(io)
#     else:
#         rs += get_rs(io, poly)
    # idx += 8
    # print(type(poly))
    # tmp = [(x & 512) == 0 for x in poly]
    # print(sum(tmp), len(tmp))
    # if all(x for x in tmp):
    #       print('Siu')
    # get_rs(io, poly)
