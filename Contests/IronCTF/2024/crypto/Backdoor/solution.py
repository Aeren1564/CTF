from CTF_Library import *

class Dual_EC:
	def __init__(self, init_state, P, Q):
		p = 229054522729978652250851640754582529779
		a = -75
		b = -250
		self.P = P
		self.Q = Q
		self.state = int(init_state)
	def set_next_state(self):
		self.state = (self.P * self.state).x()
	def gen_rand_num(self):
		rand_point = self.Q * self.state
		rand_num = rand_point.x()
		self.set_next_state()
		return rand_num

p = 229054522729978652250851640754582529779
a = -75
b = -250
F = GF(p)
EC = custom_elliptic_curve(p, [a, b])
P = EC(97396093570994028423863943496522860154, 2113909984961319354502377744504238189)
Q = EC(137281564215976890139225160114831726699, 111983247632990631097104218169731744696)

Sx = F(222485190245526863452994827085862802196)
Sy = (Sx**3 + a * Sx + b).sqrt()

prng = Dual_EC(singular_elliptic_curve_DLP(p, 0, a, b, Q, (Sx, Sy)), P, Q)
assert prng.gen_rand_num() == 222485190245526863452994827085862802196

key = long_to_bytes((prng.gen_rand_num() << 128) + prng.gen_rand_num())
iv = long_to_bytes(prng.gen_rand_num())
cipher = AES.new(key, AES.MODE_CBC, iv)
enc = b'BI\xd5\xfd\x8e\x1e(s\xb3vUhy\x96Y\x8f\xceRr\x0c\xe6\xf0\x1a\x88x\xe2\xe9M#]\xad\x99H\x13+\x9e5\xfd\x9b \xe6\xf0\xe10w\x80q\x8d'

flag = cipher.decrypt(enc)
assert b"CTF{" in flag
print(flag)
