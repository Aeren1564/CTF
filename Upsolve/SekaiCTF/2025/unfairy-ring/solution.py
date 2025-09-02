from CTF_Library import *
from uov import uov_1p_pkc as uov

names = ['Miku', 'Ichika', 'Minori', 'Kohane', 'Tsukasa', 'Kanade', 'Mai']
pks = [uov.expand_pk(uov.shake256(name.encode(), 43576)) for name in names]
goal = uov.shake256(b'SEKAI', 44)

gf = 256
n  = 112
m  = 44
v  = 68

for i in range(7):
	m1 = uov.unpack_mtri(pks[i], v)
	m2 = uov.unpack_mrect(pks[i][uov.p1_sz:], v, m)
	m3 = uov.unpack_mtri(pks[i][uov.p1_sz + uov.p2_sz:], m)
	
