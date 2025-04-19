def pick_subset_with_given_xor(values : list, target : int):
	values, target = list(map(int, values)), int(target)
	assert all(x >= 0 for x in values) and target >= 0
	dim = target.bit_length()
	for x in values:
		dim = max(dim, x.bit_length())
	from linear_equation_solver_GF2 import linear_equation_solver_GF2
	solver = linear_equation_solver_GF2(len(values))
	for d in range(dim):
		equation = 0
		for i, x in enumerate(values):
			if x >> d & 1:
				equation |= 1 << i
		if not solver.add_equation_if_consistent(equation, target >> d & 1):
			return None
	res = solver.solve()[0]
	s = 0
	for i, x in enumerate(values):
		if res >> i & 1:
			s ^= x
	assert s == target
	return [i for i in range(len(values)) if res >> i & 1]
