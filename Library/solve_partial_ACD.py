from sage.all import *
proof.all(False)
# Source: https://eprint.iacr.org/2024/1125.pdf
# 'A'pproximate 'C'ommon 'D'ivisor problem
# Given s_i, recover q from the set of equations s_i = r_i + q * p_i where 0 <= r_i < 2**rho and q.bit_length() > rho
def solve_ACD(rho : int, s : list):
	assert len(s) > 0
	s = [int(x) for x in reversed(sorted(s))]
	p0 = block_matrix([
		[matrix([2**rho]), matrix(s[1 : ])],
		[zero_matrix(len(s) - 1, 1), -s[0] * identity_matrix(len(s) - 1)]
	]).LLL()[0][0] >> rho
	return (s[0] - s[0] % p0) // p0
