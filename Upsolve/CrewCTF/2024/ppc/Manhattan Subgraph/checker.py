from hints import hints
from answer import solutions
from ciphertext import iv,ct
from hashlib import sha1,sha256
from Crypto.Cipher import AES

n=40

def sha1digest(vis):
	h = sha1()
	st=""
	for i in range(n):
		for j in range(n):
			for k in range(n):
				st+=str(int(vis[i][j][k]))
	h.update(st.encode())
	return h.digest()
	
def sha256digest(vis):
	h = sha256()
	st=""
	for i in range(n):
		for j in range(n):
			for k in range(n):
				st+=str(int(vis[i][j][k]))
	h.update(st.encode())
	return h.digest()


key=b""
cnt=0
for (a,b) in zip(solutions,hints):
	cnt+=1
	key+=sha256digest(a)
	if sha1digest(a)==b:
		print(f"AC on test {cnt}")
	else:
		print(f"WA on test {cnt}")

key=sha256(key).digest()

cipher = AES.new(key, AES.MODE_CBC,iv=iv)
print(cipher.decrypt(ct))
