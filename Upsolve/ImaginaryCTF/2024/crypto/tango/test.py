import zlib

def crc32(msg):
	crc = 0xffffffff
	for b in msg:
		crc ^= b
		for _ in range(8):
			crc = (crc >> 1) ^ 0xedb88320 if crc & 1 else crc >> 1
	return crc ^ 0xffffffff

a = b"\x00sdfadasfasdfwefreggredsdfzsdfsdfwefzdsdzfdzsdfsdfdfgergrttertr"
b = b"\xa7sdfadasfasdfwefreggredsdfzsdfsdfwefzdsdzfdzsdfsdfdfgergrttertr"

c = b""
for _ in range(len(a) - 1):
	c += b"\x00"
c = b"\xa7" + c

d = bytes([0] * 63)

assert (crc32(a) ^ crc32(c) ^ crc32(d)) == crc32(b)

data = b'{"user": "user", "command": "AAA", "nonce": "4af020448beb51eb"}'

found = []
for x in "0123456789abcdef":
	for y in "0123456789abcdef":
		found.append(ord(x) ^ ord(y))

found = sorted(found)
print(found)