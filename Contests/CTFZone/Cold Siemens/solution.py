from CTF_Library import *

# nc = remote("cold-siemens.ctfz.zone", 1188)
# print(nc.recvline())
nc = process(["python3", "cold_siemens.py"])

print(nc.recvuntil(b"Encrypted flag: "))
enc_flag = nc.recvline()
print(f"{enc_flag = }")

key = []
cnt = [0] * 2**8
prec = 285
for l in range(1, prec + 1):
	nc.recvuntil(b"m: ")
	nc.sendline(bytes([0] * l))
	print(nc.recvuntil(b"Encrypted msg: "))
	cnt_next = [0] * 2**8
	for x in nc.recvline().strip():
		cnt_next[x] += 1
	for x in range(2 ** 8):
		if cnt[x] != cnt_next[x]:
			key.append(x)
			break
	assert len(key) == l
	cnt = cnt_next
	