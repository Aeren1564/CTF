def half_gcd(a: int, b: int):
	a, b = abs(int(a)), abs(int(b))
	if a == 0 or b == 0:
		return a | b
	# TODO: finish