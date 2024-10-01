from CTF_Library import *

def aes(block: bytes, key: bytes) -> bytes:
	assert len(block) == len(key) == 16
	return AES.new(key, AES.MODE_ECB).encrypt(block)

def pad(data):
	padding_length = 16 - len(data) % 16
	return data + b"_" * padding_length

def hash(data: bytes):
	data = pad(data)
	state = bytes.fromhex("f7c51cbd3ca7fe29277ff750e762eb19")

	for i in range(0, len(data), 16):
		block = data[i : i + 16]
		state = aes(block, state)

	return state

with remote("challs.pwnoh.io", 13419) as io:
	io.readuntil(b"hex:\n")
	m = pad(bytes.fromhex(io.readline().strip().decode()))
	io.readuntil(b"Signature:\n")
	key = bytes.fromhex(io.readline().strip().decode())
	m += b"french fry"
	io.sendline(m.hex())
	io.sendline(AES.new(key, AES.MODE_ECB).encrypt(pad(b"french fry")).hex())
	print(io.readallS())
