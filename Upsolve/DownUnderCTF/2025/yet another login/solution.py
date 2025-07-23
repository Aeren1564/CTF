from CTF_Library import *

with process(["python3", "chall.py"]) as io:
# with remote("chal.2025-us.ductf.net", 30010) as io:
	n = int(io.readlineS().strip())
	def register(msg):
		io.sendlineafter(b"> ", b"1")
		io.sendlineafter(b"Username: ", msg)
		io.readuntil(b"Token: ")
		msg2, _, mac = bytes.fromhex(io.readlineS().strip()).partition(b"|")
		assert msg2 == b"user=" + msg
		return msg2, mac
	def verify(msg, mac):
		io.sendlineafter(b"> ", b"2")
		io.sendlineafter(b"Token: ", (msg + b"|" + mac).hex().encode())
		resp = io.readlineS().strip()
		return resp.startswith("Welcome")
	c_aeren = bytes_to_long(register(b"aeren")[1])
	h_aeren = 0
	assert verify(b"user=aeren", long_to_bytes(c_aeren))
	for bit in range(256):
		print(f"{bit = }")
		shift = 2**(255 - bit)
		if not verify(b"user=aeren", long_to_bytes(pow(c_aeren, shift + 1, n**2) * (1 - n * h_aeren * shift) % n**2)):
			h_aeren |= 1 << bit
	assert verify(b"user=aeren", long_to_bytes(c_aeren**2 * (1 - n * h_aeren) % n**2))
	sha = SHA256(16, b"user=aeren", long_to_bytes(h_aeren)).extend(b"user=admin")
	m_admin = sha.get_plaintext()
	h_admin = sha.digest()
	assert verify(m_admin, long_to_bytes(1 + n * bytes_to_long(h_admin)))
	print(io.readlineS().strip())
