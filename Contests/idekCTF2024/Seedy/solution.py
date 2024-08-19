from CTF_Library import *
import random

with open("output.txt", 'r') as f:
	out	=	f.read().strip()

num = 11000
twister = symbolic_mersenne_twister(624)

outputs = [int(out[i]) for i in range(num)]
equations = [ twister.getrandbits(1) for _ in range(num) ]

solver = linear_equation_solver_F2()

for i in range(0, 32):
	assert solver.add_equation(1 << i, int(i == 31))
for i in range(num):
	assert solver.add_equation(equations[i][0], outputs[i] & 1)

state = solver.solve()
state = [state >> (32 * i) & 0xFFFFFFFF for i in range(624)]
recovered_state = (3, tuple(state + [624]), None)

print(f'{recovered_state = }')

random.setstate(recovered_state)

assert recovered_state[1][0] == 2147483648

for i in range(len(out)):
	if int(out[i]) != random.getrandbits(1):
		print("Incorrect value at", i)
		assert False
