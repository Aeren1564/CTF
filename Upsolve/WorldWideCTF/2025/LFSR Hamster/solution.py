from pwn import *

flag_len = 8 * 21 # 21 bytes
n = 2 * 10**7
connection_chunk = 10**4
chunk = 10**3

def get_bit(b, i):
	return b[i >> 3] >> 7 - (i & 7) & 1
def set_bit(b, i, x):
	b[i >> 3] |= x << 7 - (bit & 7)

cnt = [[0, 0] for _ in range(8 * 21)]
for _ in range(n // connection_chunk):
	print(f"Connection {_ + 1}/{n // connection_chunk}")
	encs = []
	with process(["python3", "chall.py"]) as io:
	# with remote("chal.wwctf.com", 8005) as io:
		for _ in range(connection_chunk // chunk):
			print(f"Chunk #{_}")
			for _ in range(chunk):
				io.sendline(b"enc")
				io.sendline(b"0" * 32)
				io.sendline(b"flag")
			data = io.readlinesS(2 * chunk)
			for i in range(0, 2 * chunk, 2):
				encs.append(bytes.fromhex(data[i][2:]) + bytes.fromhex(data[i + 1][1:]))
	for enc in encs:
		for bit in range(flag_len):
			cnt[bit][
				get_bit(enc, bit) ^
				get_bit(enc, bit + 1) ^
				get_bit(enc, bit + 2) ^
				get_bit(enc, bit + 7) ^
				get_bit(enc, bit + 128)
			] += 1
	flag = [0] * (flag_len // 8)
	for bit in range(flag_len):
		x = int(cnt[bit][0] < cnt[bit][1])
		for pbit in [bit - 128, bit - 127, bit - 126, bit - 121]:
			if pbit >= 0:
				x ^= get_bit(flag, pbit)
		set_bit(flag, bit, x)
	flag = bytes(flag)
	print(f"{flag = }")
	print()
