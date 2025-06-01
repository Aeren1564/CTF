from CTF_Library import *

h1 = 'your number is too big'
h2 = 'your number is too small'
h3 = 'you win'

with process(["python3", "chal.py"]) as io:
	breaker = mersenne_twister_breaker()
	breaker.init_state_after_seeding()
	rng_call_cnt = 0

	print(f"Mode 0")
	jump = 2**32 // 6 + 1
	for rnd in range(350):
		print(f"{rnd = }")
		rng_call_cnt += 1
		eq_res = breaker.setrandbits(32)[:]
		interact_cnt = 0
		def interact(x):
			global rng_call_cnt
			global interact_cnt
			interact_cnt += 1
			assert interact_cnt <= 32
			io.sendlineafter(b"> ", str(x).encode())
			resp = io.readlineS().strip()
			if resp != h3:
				rng_call_cnt += 2
				breaker.setrandbits(32)
				breaker.setrandbits(32)
			return resp
		val0 = interact(0)
		assert val0 != h3
		cut = (5 - ["0.075", "0.15", "0.225", "0.3", "0.375", "0.45"].index(val0)) * jump
		won = False
		def pred(x):
			global won
			if won:
				print(f"Already won")
				return True
			resp = interact(x)
			if resp == h3:
				won = True
				breaker.add_equation(eq_res, x - 1)
				return True
			return resp != "0.45"
		res = partition_point(cut - jump, cut, pred) + jump - 1
		if won:
			continue
		assert interact(res) == h3
		breaker.add_equation(eq_res, res - 1)
	print(f"{breaker.rank() = }")
	print(f"{breaker.nullity() = }")
	print()

	print()
	print(f"Mode 1-0")
	rnd = -1
	while rnd + 1 < 2200:
		rnd += 1
		print(f"{rnd = }")
		rng_call_cnt += 1
		eq_res = breaker.setrandbits(32)
		bbs = Bayesian_binary_searcher(1, 2**32 - 1)
		for turn in range(64):
			x = bbs.half_index() if turn < 63 else bbs.guess_ans()
			io.sendlineafter(b"> ", str(x).encode())
			resp = io.readlineS().strip()
			if resp == h3:
				breaker.add_equation(eq_res, x - 1)
				print(f"Won with guess {x}")
				print(f"{breaker.rank() = }")
				print(f"{breaker.nullity() = }")
				break
			rng_call_cnt += 2
			breaker.setrandbits(32)
			breaker.setrandbits(32)
			if resp == h1:
				bbs.update(x, (0.9, 0, 0.1))
			else:
				bbs.update(x, (0.1, 0, 0.9))
		else:
			print(f"Lost")
			print(f"{breaker.rank() = }")
			print(f"{breaker.nullity() = }")
		if breaker.nullity() == 0:
			break
	random.setstate(breaker.recover())
	for _ in range(rng_call_cnt):
		random.getrandbits(32)

	print()
	print(f"Mode 1-1")
	while rnd + 1 < 2200:
		rnd += 1
		print(f"{rnd = }")
		io.sendlineafter(b"> ", str(random.randint(1, 2**32 - 1)).encode())
		assert io.readlineS().strip() == h3
	print(f"{io.readallS(timeout = 1)}")
