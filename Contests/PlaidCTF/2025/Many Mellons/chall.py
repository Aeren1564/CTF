from random import randint

beta=[[0,0,0,1,0,1,0,1,1,0,1,1,0,0,1,1],[0,1,1,1,1,0,0,0,1,1,0,0,0,0,0,0],[1,0,1,0,0,1,0,0,0,0,1,1,0,1,0,1],[0,1,1,0,0,0,1,0,0,0,0,1,0,0,1,1],[0,0,0,1,0,0,0,0,0,1,0,0,1,1,1,1],[1,1,0,1,0,0,0,1,0,1,1,1,0,0,0,0],[0,0,0,0,0,0,1,0,0,1,1,0,0,1,1,0],[0,0,0,0,1,0,1,1,1,1,0,0,1,1,0,0],[1,0,0,1,0,1,0,0,1,0,0,0,0,0,0,1],[0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0],[0,1,1,1,0,0,0,1,1,0,0,1,0,1,1,1],[0,0,1,0,0,0,1,0,1,0,0,0,1,1,1,0],[0,1,0,1,0,0,0,1,0,0,1,1,0,0,0,0],[1,1,1,1,1,0,0,0,1,1,0,0,1,0,1,0],[1,1,0,1,1,1,1,1,1,0,0,1,0,0,0,0]]
S = [0xc,0xa,0xd,0x3,0xe,0xb,0xf,0x7,0x8,0x9,0x1,0x5,0x0,0x2,0x4,0x6]
P = [0,10,5,15,14,4,11,1,9,3,12,6,7,13,2,8]
def encrypt_block(plainText, WK, K0, K1):
  state = [a ^ b for a, b in zip(WK, plainText)]
  sched = [K0, K1, K0, K1, K0, K1, K0, K1, K0, K1, K0, K1, K0, K1, K0]
  for i in range(15):
    for j in range(16):
      state[j] = S[state[j]]

    tmp = state[:]
    for j in range(16):
      tmp[j] = state[P[j]]
    state = tmp

    tmp = state[:]
    for j in range(0, 16, 4):
      state[j] = tmp[j+1] ^ tmp[j+2] ^ tmp[j+3]
      state[j+1] = tmp[j] ^ tmp[j+2] ^ tmp[j+3]
      state[j+2] = tmp[j] ^ tmp[j+1] ^ tmp[j+3]
      state[j+3] = tmp[j] ^ tmp[j+1] ^ tmp[j+2]

    state = [a^b for a, b in zip(state, [x ^ y for (x, y) in zip(beta[i], sched[i])])]

  for j in range(16):
    state[j] = S[state[j]]

  return [a ^ b for a, b in zip(WK, state)]

def split_nibbles(l):
  res = []
  for i in l:
    res.append((i >> 4) & 0xf)
    res.append(i & 0xf)
  return res

def unsplit_nibbles(l):
  res = []
  for i in range(0, len(l), 2):
    res.append((l[i] << 4) | l[i+1])
  return res

def compress(message_bytes):
  output = []
  for b in message_bytes:
    assert b & 0x80 == 0
    output.append(format(b, '07b'))
  output_str = ''.join(output)
  if len(output_str) % 8 != 0:
    output_str += '0' * (8 - (len(output_str) % 8))
  res = []
  for i in range(0, len(output_str), 8):
    res.append(int(output_str[i:i+8], 2))
  return res

def decompress(message_bytes):
  bits = []
  for b in message_bytes:
    bits.append(format(b, '08b'))
  bitstr = ''.join(bits)
  bitstr = bitstr[:-(len(bitstr) % 7)]
  output = []
  for i in range(0, len(bitstr), 7):
    output.append(int(bitstr[i:i+7], 2))
  return output

def encrypt(key, message):
  key = split_nibbles(key)
  K0 = key[:16]
  K1 = key[16:32]
  WK = [a ^ b for a,b in zip(K0, K1)]
  padding_needed = 8 - (len(message) % 8)
  message = split_nibbles(list(message) + padding_needed * [padding_needed])
  assert len(message) % 16 == 0
  assert len(message) > 0
  blocks = [message[i:i+16] for i in range(0, len(message), 16)]
  iv = split_nibbles([randint(0,255) for _ in range(8)])
  output = list(iv)
  for block in blocks:
    pt = [a ^ b for (a,b) in zip(block, iv)]
    ct = encrypt_block(pt, WK, K0, K1)
    assert len(ct) == 16
    output.extend(ct)
    iv = ct
  assert all(c < 0x10 for c in output)
  return unsplit_nibbles(output)

if __name__ == '__main__':
  with open('key.bin', 'rb') as f:
    key = f.read()
    assert len(key) == 16
    assert 32 < sum(k.bit_count() for k in key) <= 64
  with open('flag.txt', 'rb') as f:
    flag = f.read().strip()
    assert len(flag) == 41, len(flag)

  message = compress(b'PPPMSG:PPPMSG:' + (b'PCTF{' + flag + b'}') * 3000)
  ciphertext = bytes(encrypt(key, message))
  with open('ct0.bin', 'wb') as f:
    f.write(ciphertext)

  verification = compress(b'P' * 7000)
  with open('ct1.bin', 'wb') as f:
    f.write(bytes(encrypt(key, verification)))

