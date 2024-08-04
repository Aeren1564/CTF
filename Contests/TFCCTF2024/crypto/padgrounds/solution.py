from pwn import *
from Crypto.Cipher import AES
import base64

#nc = remote('exploitme.example.com', 31337)
nc = process(["python3.8", "server.py"])

print(nc.recvuntil(b"Lets see you decode this: "))
given = base64.b64decode(nc.recvline().strip())
iv, ct = given[ : 16], given[16 : ]
print(f"{len(iv) = }")
print(f"{iv = }")
print(f"{len(ct) = }")
print(f"{ct = }")
print(nc.recvline())
print()

def send(s: bytearray):
	nc.sendline(base64.b64encode(s))

stream = []
for block in range(0, len(ct) // 16):
	cur_stream = [-1] * 16
	for i in range(15, -1, -1):
		pad_length = 16 - i
		for x in range(1 << 8):
			resp = False
			cnt = [0, 0]
			for _ in range(10):
				send(bytearray(iv) + bytearray([0] * (16 * block + i) + [x] + [y ^ pad_length for y in cur_stream[i + 1 : ]]))
				response = nc.recvline().strip()
				assert response == b"True" or response == b"False"
				cnt[response == b"True"] += 1
			if cnt[0] < cnt[1]:
				cur_stream[i] = x ^ pad_length ^ ct[16 * block + i]
				break
		print(f"Answer for index {16 * block + i} = {cur_stream[i]}")
		assert cur_stream[i] != -1
	print(cur_stream)
	stream += cur_stream

flag = bytes([int(x) ^ int(y) for x, y in zip(ct, stream)])
print(f"{flag = }")
