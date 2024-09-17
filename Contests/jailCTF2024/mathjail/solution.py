from CTF_Library import *

#Best so far: 126
# expr = """(n-n)**((((n+n+n+n)*(n+n+n+n)*(((n+n+n+n+n)//n)**((n+n+n+n)//n)*n+n+n+n+n+n+n)//n//n+n+n+n+n+n+n+n)//n)**(n*n-n)%n*n-n)**(n+n)
# """

expr = """
(n-n)**(
	(
		((n + n) // n)**(n - n//n) % n * n
		-n
	)%(n * n)
	*(n * n - n - n)
	+ 1
	- (n > 341)
	- (n < 341)
)
"""

# expr = """

# """

def reduced(s : str):
	res = ""
	for c in s:
		if c in "n+-*/%()0123456789><=":
			res += c
	return res

expr = reduced(expr)

print(f"{expr = }")

f = lambda n: eval(expr)

print(f"{len(expr) = }")
for i in range(499, 0, -1):
	if f(i) != int(is_prime(i)):
		print(f"{i = }")
		print(f"{f(i) = }")
		print(f"{is_prime(i) = }")
		assert False
