from sage.all import *
proof.all(False)
# Source: https://eprint.iacr.org/2024/1125.pdf
# 'A'pproximate 'C'ommon 'D'ivisor problem
# Given s_i, return p_0 which satisfies the set of equations s_i = r_i + q * p_i where 0 <= r_i < 2**len_r and q.bit_length() > len_r
# It tries to maximize q
def solve_ACD(s : list, len_r : int, len_q : int):
	s = list(map(int, s))
	assert 0 < len_r < len_q and len(s) >= 2
	len_s = max(x.bit_length() for x in s)
	assert len_q < len_s
	assert len(s) * (len_q - len_r) > (len_s - len_q)
	for row in block_matrix([[matrix([2**len_r]), matrix(s[1 : ])], [zero_matrix(len(s) - 1, 1), -s[0] * identity_matrix(len(s) - 1)]]).LLL():
		if row[0] != 0:
			return abs(row[0]) >> len_r

"""
Tested on
- AlpacaHack2024 Round 5/nnnn
- WMCTF2024/crypto/FACRT
"""