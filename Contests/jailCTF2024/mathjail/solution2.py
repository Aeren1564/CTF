from CTF_Library import *
from numpy import sqrt

base = 10103
# base = 54563
for x in range(-100, 101):
	print(x, factor(base + x))
print()

"""
-23 2^5 * 3^2 * 5 * 7
-5  2 * 3^3 * 11 * 17
17  2^3 * 5 * 11 * 23
22 3^4 * 5^3
"""

# shift = 10**7

# expr = """
# int(round(
# 	16180339**(n-1) / (22360679 * shift**(n-2))
# ))
# """

# # def reduced(s : str):
# # 	res = ""
# # 	for c in s:
# # 		if c in "n+-*/%()0123456789":
# # 			res += c
# # 	return res

# # expr = reduced(expr)

# f = lambda n: eval(expr)

# print(f"{expr = }")
# print(f"{len(expr) = }")

# fib = [0, 0, 1]
# for i in range(1, 101):
# 	fib.append(fib[-1] + fib[-2])
# 	if f(i) != fib[i]:
# 		print(f"{i = }")
# 		print(f"{f(i) = }")
# 		print(f"{fib[i] = }")
# 		assert False
