from CTF_Library import *

with open("flag-enc.bmp", "rb") as file:
	d = file.read()
	header = d[:len(d) - 1024 ** 2 * 3]
	enc_data = d[len(d) - 1024 ** 2 * 3:]

print(f"Data size = {3 * 2**20}")
# Windows BITMAPINFOHEADER
print(f"{len(header) = }")
# b"BM"
print("BM", header[:2])
print("width  in pixel", int.from_bytes(header[18:22], byteorder = "little"))
print("height in pixel", int.from_bytes(header[22:26], byteorder = "little"))
print("# of color planes", int.from_bytes(header[26:28], byteorder = "little"))
print("# of bits per pixel", int.from_bytes(header[28:30], byteorder = "little"))
print("compression method", int.from_bytes(header[30:34], byteorder = "little"))
print("image size", int.from_bytes(header[34:38], byteorder = "little"))
print("horizontal resolution", int.from_bytes(header[38:42], byteorder = "little"))
print("vertical   resolution", int.from_bytes(header[42:46], byteorder = "little"))
print("# of colors in the color palette", int.from_bytes(header[46:50], byteorder = "little"))
print("# of important colors used", int.from_bytes(header[50:54], byteorder = "little"))

keys0 = [bytes(3) for _ in range(20)]
keys1 = [bytes(3) for _ in range(20)]
for pos in range(20):
	jump = 2**pos
	cnt = [0] * 2**24
	for i in range(0, 2**20):
		if ~i >> pos & 1:
			cnt[
				bytes_to_long(enc_data[3 * i : 3 * (i + 1)]) ^
				bytes_to_long(enc_data[3 * (i + jump) : 3 * (i + jump + 1)])
			] += 1
	keys1[19 - pos] = long_to_bytes(max(range(len(cnt)), key = lambda x: cnt[x]), 3)
	print(f"{pos = }, {keys1[19 - pos] = }, {cnt[bytes_to_long(keys1[19 - pos])] = }")

def xor(x, y):
	return bytes([a ^ b for a, b in zip(x, y)])

def stream(keys0, keys1):
	for keys in itertools.product(*zip(keys0, keys1)):
		key = reduce(xor, keys)
		yield key
ks = stream(keys0, keys1)

chunked = itertools.zip_longest(*[iter(enc_data)] * 3)
decrypted = [
	xor(chunk, next(ks))
	for chunk in chunked
]

with open('flag.bmp', 'wb') as f:
	f.write(header)
	f.write(b''.join(decrypted))
