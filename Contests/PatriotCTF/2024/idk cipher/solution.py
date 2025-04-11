import base64

ct = "QRVWUFdWEUpdXEVGCF8DVEoYEEIBBlEAE0dQAURFD1I="

ct = base64.b64decode(ct.encode())
print(f"{ct = }")

secret = 'secretkey'
user = [0] * len(ct)
l, r = 0, len(ct) - 1
pool = "0123456789abcdefghijklmnopqweruvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
for i in range(0, len(ct), 2):
	user[l] = ct[i] ^ ord(secret[l % len(secret)])
	user[r] = ct[i + 1] ^ ord(secret[l % len(secret)])
	l += 1
	r -= 1

print(f"{bytes(user).decode()}")