from Crypto.Cipher import Salsa20
from Crypto.Util.number import bytes_to_long, long_to_bytes
import json
from secrets import token_bytes, token_hex
from zlib import crc32
from pwn import *

def encrypt_command(key, nonce, nonce2, user, command):
	cipher = Salsa20.new(key = key, nonce = nonce)
	data = json.dumps({'user': user, 'command': command, 'nonce': nonce2}).encode('ascii')
	checksum = crc32(data)
	ciphertext = cipher.encrypt(data)
	
	checksum = long_to_bytes(checksum)
	return (nonce + checksum + ciphertext).hex()

def swap_user_with_root(packet):
	packet = bytes.fromhex(packet)
	nonce, checksum, ciphertext = packet[: 8], bytes_to_long(packet[8 : 12]), packet[12 : ]
	
	swapper = [0] * 63
	swapper[10] = ord('u') ^ ord('r')
	swapper[11] = ord('s') ^ ord('o')
	swapper[12] = ord('e') ^ ord('o')
	swapper[13] = ord('r') ^ ord('t')
	swapper = bytes(swapper)
	checksum ^= crc32(bytes([0] * 63)) ^ crc32(swapper)
	ciphertext = bytes(x ^ y for x, y in zip(ciphertext, swapper))

	checksum = long_to_bytes(checksum)
	return (nonce + checksum + ciphertext).hex()

def _sanity_check_swap_user_with_root():
	key = b'4\x12\x00\xcf\xf6|1oO\xdb\xef\xc6\xa1\x12\x11\x14\xbc\x8d0Wi\xd3j\xa5\xccR\x18\xa3k7\xee\xda'
	nonce = b';al\x9d\xdbV-2'
	nonce2 = "4af020448beb51eb"

	packet0 = swap_user_with_root(encrypt_command(key, nonce, nonce2, "user", "zA_"))
	packet1 = encrypt_command(key, nonce, nonce2, "root", "zA_")
	assert packet0 == packet1
_sanity_check_swap_user_with_root()

def shift_by_g(packet):
	packet = bytes.fromhex(packet)
	nonce, checksum, ciphertext = packet[: 8], bytes_to_long(packet[8 : 12]), packet[12 : ]

	packets = []
	for first in b"0123456789abcdef":
		for extra_cipher in range(1 << 8):
			s_from = bytes([0] * 32) + b'", "nonce": "' + bytes([first]) + bytes([0] * 15) + b'"}'
			s_to   = bytes([0] * 32) + b'g", "nonce": "'                 + bytes([0] * 15) + b'0"'
			assert(len(s_from) == 63 and len(s_to) == 63)
			checksum_next = crc32(b'}', checksum ^ crc32(s_from) ^ crc32(s_to))
			ciphertext_next = bytes(x ^ y ^ z for x, y, z in zip(ciphertext, s_from, s_to)) + bytes([extra_cipher ^ ord('}')])
			packets.append((nonce + long_to_bytes(checksum_next) + ciphertext_next).hex())
	return packets

def _sanity_check_shift_by_g():
	key = b'4\x12\x00\xcf\xf6|1oO\xdb\xef\xc6\xa1\x12\x11\x14\xbc\x8d0Wi\xd3j\xa5\xccR\x18\xa3k7\xee\xda'
	nonce = b';al\x9d\xdbV-2'
	nonce2 = "faf010448beb51eb"
	packets = shift_by_g(encrypt_command(key, nonce, nonce2, "root", "fla"))
	packet = bytes.fromhex(encrypt_command(key, nonce, nonce2[1 : ] + "0", "root", "flag"))

	nonce, checksum, ciphertext = packet[ : 8], bytes_to_long(packet[8 : 12]), packet[12 : ]

	cipher = Salsa20.new(key=key, nonce=nonce)
	plaintext = cipher.decrypt(ciphertext)

	print(plaintext)

	assert packet.hex() in packets
	assert crc32(plaintext) == checksum

_sanity_check_shift_by_g()

nc = remote('tango.chal.imaginaryctf.org', 1337)
print(nc.recvuntil(b'== proof-of-work: '), nc.recvline())

# E
print(nc.recvuntil(b"> "))
nc.sendline(b"E")
print(nc.recvuntil(b"Your command: "))
nc.sendline(b"fla")
print(nc.recvuntil(b"Your encrypted packet is: "))
packet = nc.recvline().decode().strip()
print("packet = ", packet)

packets = shift_by_g(swap_user_with_root(packet))

# R
for packet in packets:
	print(nc.recvuntil(b"> "))
	nc.sendline(b"R")
	print(nc.recvuntil(b"Your encrypted packet (hex): "), packet)
	nc.sendline(packet.encode())
	resp = nc.recvline().decode().strip()
	print(f"{resp = }")
	if resp == "Invalid data. Aborting!":
		print("Fail: invalid data")
		continue
	if resp == "Invalid checksum. Aborting!":
		print("Fail: invalid checksum")
		continue
	if resp == "Unknown command.":
		print("Fail: Unknown command")
		exit(0)
	exit(0)

print("Dead end")