from CTF_Library import *

hint = []
with open("output.txt") as file:
	file.readline()
	enc_flag = bytes.fromhex(file.readline().strip())
	file.readline()
	for _ in range(50):
		x = int(file.readline().strip())
		hint.append(x)
# check if any quotient is 0
for i in range(49):
	ac = hint[i] ^ hint[i + 1]
	m = -1
	fail = False
	for j in range(49):
		if hint[j] ^ ac == hint[j + 1]:
			continue
		dif = (hint[j] ^ ac) - hint[j + 1]
		if dif < 0 or not is_prime(dif) and (dif % 2 == 1 or not is_prime(dif // 2)):
			fail = True
			break
		cm = dif if is_prime(dif) else dif // 2
		assert is_prime(cm)
		if m != -1 and m != cm:
			fail = True
			break
		m = cm
	assert fail # quotient is 1 or 2
def solve_for_mask(mask):
	ac, m = 0, 0
	for bit in range(300):
		mod = 2**(bit + 1)
		for bit_mask in range(4):
			ac_next = ac | (bit_mask & 1) << bit
			m_next = m | (bit_mask >> 1 & 1) << bit
			def check(i):
				x, y = (hint[i] ^ ac_next) % mod, (hint[i + 1] + (m_next if mask >> i & 1 == 1 else 2 * m_next)) % mod
				return x == y
			if all(check(i) for i in range(10)):
				ac = ac_next
				m = m_next
				break
		else:
			return None, None
	return ac, m
for mask in range(1 << 10):
	ac, m = solve_for_mask(mask)
	if ac and m:
		break
print(f"{ac = }, {m = }")
for mask in range(3**4):
	prev = [hint[0]]
	for i in range(4):
		x = prev[-1] + (mask % 3**(i + 1) // 3**i) * m ^ ac
		if x >= m:
			break
		prev.append(x)
	else:
		raw_keys = [long_to_bytes(prev[4]), long_to_bytes(prev[3])]
		raw_nonce = [long_to_bytes(prev[2]), long_to_bytes(prev[1])]
		key = SHA256.new(b"".join(raw_keys)).digest()
		nonce = SHA256.new(b"".join(raw_nonce)).digest()
		flag = AES.new(key=key, mode=AES.MODE_CTR, nonce=nonce[:12]).decrypt(enc_flag)
		print(f"{flag}")
