from CTF_Library import *
from uov import uov_1p_pkc as uov

msg = b"Aeren"
key = b"\x00" * 16
iv  = b'\x00' * 0
aes = AES.new(key, AES.MODE_CTR, nonce=iv, initial_value=0)

for l in range(0, 20):
	print(f"{l = }")
	print(f"{aes.encrypt(b"\x00" * l) = }")
	assert l == len(aes.encrypt(b"\x00" * l))
	print()

"""
gf = 256
n  = 112
m  = 44
v  = 68 (n - m)
pkc = True
skc = False

gf_bits = 8

v_sz   =   gf_bits * v // 8  #   _V_BYTE
n_sz   =   gf_bits * n // 8  #   _PUB_N_BYTE
m_sz   =   gf_bits * m // 8  #   _PUB_M_BYTE, _O_BYTE

seed_sk_sz =   32              #   LEN_SKSEED
seed_pk_sz =   16              #   LEN_PKSEED
salt_sz    =   16              #   _SALT_BYTE

sig_sz =   n_sz + salt_sz        #   OV_SIGNATUREBYTES
so_sz  =   m * v_sz              #

p1_sz  =   m_sz * triangle(v)    #   _PK_P1_BYTE
p2_sz  =   m_sz * v * m          #   _PK_P2_BYTE
p3_sz  =   m_sz * triangle(m)    #   _PK_P3_BYTE

pk_sz  =   seed_pk_sz + p3_sz                   #   |cpk|
sk_sz  =   seed_sk_sz + so_sz + p1_sz + p2_sz   #   |esk|


<expand_p(seed_pk)>
pk = aesctr(seed_pk, p1_sz + p2_sz)
return pk[:p1_sz], pk[p1_sz:]

<expand_pk(cpk)>
len(cpk) == 43576
seed_pk = cpk[:16]           # len 16
p3 = cpk[16:]                # len 43560
p1, p2 = expand_p(seed_pk)
return p1+p2+p3

<unpack_mtri(b, d)>
unpacks b into d by d upper triangular matrix
each element is m_sz bytes

<unpack_mtri(b, h, w)>
unpacks b into h by w upper triangular matrix
each element is m_sz bytes

<gf_unpack(b)>
unpacks b into m_sz bytes

<pubmap(z, tm)>
returns z^T * tm * z

pks[i] = expand_pk(shake256(name, 43576))
sig <- I give them, len(sig) == 112 * len(names)

goal: uov.shake256(msg, 44) == xor(pubmap(sig[112 * i : 112 * (i + 1)], pks[i]) for i in range(7))


obj[id] = sum_i(sig[i].T * M[id][i] * sig[i])

sig[i]: dimension n vector over GF(256)

v[i][0] -> null dim n-1 -> intersection dim n-m
v[i][1] -> null dim n-2 -> intersection dim n-2*m
v[i][2]
v[i][3]
v[i][4]

let q[id][i][j] = v[i][j].T * M[id][i] * v[i][j]

sig[i] = sum_j(c[i][j] * v[i][j])

ob[id]
= sum_i(sig[i].T * M[id][i] * sig[i])
= sum_i(sum_j(c[i][j] * v[i][j]).T * M[id][i] * sum_j(c[i][j] * v[i][j]))
= sum_{i,j}(c[i][j]^2 * q[id][i][j])
"""