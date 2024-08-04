import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
x = 11131221131211131231121113112221121321132132211331222113112211

def get_next(x: int):
	x = str(x)
	l, r = 0, 0
	y = ""
	while l < len(x):
		r = l
		while r < len(x) and x[l] == x[r]:
			r += 1
		y += chr(ord('0') + r - l) + x[l]
		l = r
	return int(y)

x = get_next(x)
print(x)
x = get_next(x)
h = hashlib.sha256()
h.update(str(x).encode())
key = h.digest()

ct = "f143845f3c4d9ad024ac8f76592352127651ff4d8c35e48ca9337422a0d7f20ec0c2baf530695c150efff20bbc17ca4c"

cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(bytes.fromhex(ct)))