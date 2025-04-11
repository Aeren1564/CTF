import secrets

cnt = [0] * 296
flag = "TEST_FLAG{12332424524}"
while len(flag) < 296 // 8:
    flag += '?'

def share_bits_with_you(flag):
    # Convert the flag to its binary representation
    flag_bits = ''.join(f'{ord(c):08b}' for c in flag)
    num_bits = len(flag_bits)
    indices = list(range(num_bits))
    
    # Fisher-Yates shuffle to mix up the bits
    for i in range(num_bits - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        indices[i], indices[j] = indices[j], indices[i]
    
    # Split the bits: half for you, half for me :3
    boyfriend_indices = indices[:num_bits // 2]
    for i in range(num_bits // 2):
        cnt[boyfriend_indices[i]] += 1

# Share the bits 1000000 times <3 <3 <3
for _ in range(100000):
    if (_ + 1) % 10000 == 0:
        print(f"Round {_ + 1}")
    share_bits_with_you(flag)

print(cnt)