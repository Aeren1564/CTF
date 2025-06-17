from CTF_Library import *
from Crypto.Util.number import isPrime

def getRandomInteger(N, randfunc):
	S = randfunc(N>>3)
	odd_bits = N % 8
	if odd_bits != 0:
		rand_bits = ord(randfunc(1)) >> (8-odd_bits)
		S = struct.pack('B', rand_bits) + S
	value = bytes_to_long(S)
	return value

def getRandomRange(a, b, randfunc):
	range_ = b - a - 1
	bits = range_.bit_length()
	value = getRandomInteger(bits, randfunc)
	while value > range_:
		value = getRandomInteger(bits, randfunc)
	return a + value

randf = lambda nbits: random.randint(13, 37).to_bytes(nbits, 'big')
bases = list(x for x in range(15, 40) if is_prime(x))
print(f"{bases = }")
liars = [(56897193526942024370326972321, 0, 0, 0)]
liars += generate_strong_pseudoprime_2(bases, 100, 1336, lambda x, p1, p2: isPrime(x, randfunc=randf) and isPrime(x, randfunc=randf) and isPrime(x, randfunc=randf) and isPrime(x, randfunc=randf) and isPrime(x, randfunc=randf))
print(f"{liars = }")

with process(["python3", "server.py"]) as io:
	def proof_of_work():
		io.readuntil(b"prefix (hex): ")
		prefix = bytes.fromhex(io.readlineS().strip())
		while True:
			ans = os.urandom(10)
			if int(hashlib.sha256(prefix + ans).hexdigest(), 16) & (0xFFFFFF << 232) == 0:
				io.readuntil(b"ans (hex): ")
				io.sendline(ans.hex().encode())
				break
	#proof_of_work()
	print(f"PoW Done")
	data = []
	for liar, _0, _1, _2 in liars:
		print(f"{liar = }")
		io.readuntil(b"Prime number: ")
		io.sendline(str(liar).encode())
		resp = io.readlineS().strip()
		print(f"{resp = }")
		if resp[:3] == "The": 
			res = int(resp.split(": ")[1])
			data.append((liar, res))
	print(f"Data collection finished")
	print(f"{data = }")
	for x in range(256**3):
		if is_prime(x):
			def check(liar, res):
				return pow(x, liar - 1, liar) == res
			if all(check(*args) for args in data):
				io.readuntil(b"What is my leet prime: ")
				io.sendline(str(x).encode())
				io.readallS(timeout = 1)
				exit(0)
