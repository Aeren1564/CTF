# # Source:
# # - https://connor-mccartney.github.io/cryptography/rsa/CyclotomicPolynomial
# # - "Factoring with Cyclotomic Polynomials" (https://www.ams.org/journals/mcom/1989-52-185/S0025-5718-1989-0947467-1/S0025-5718-1989-0947467-1.pdf)
# # Find any non-trivial prime factor p of n
# # We're given a hint which is a multiple of phi_k(p), where phi_k is the k-th cyclotomic polynomial
# def find_a_factor_with_cyclotomic_polynomial(n, hint, k):
# 	from sage.all import is_prime
# 	assert n >= 2 and hint >= 2 and k >= 1
# 	m = 1
# 	while True:

# 		m += k


# if __name__ == "__main__":
# 	from sage.all import cyclotomic_polynomial
# 	for k in range(1, 10):
# 		print(cyclotomic_polynomial(k))
# 		print(cyclotomic_polynomial(k)(1))
