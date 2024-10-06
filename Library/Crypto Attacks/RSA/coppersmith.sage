# Source: https://raw.githubusercontent.com/Connor-McCartney/coppersmith/refs/heads/main/coppersmith.sage

"""
References:

https://www.iacr.org/archive/asiacrypt2008/53500412/53500412.pdf
https://gist.github.com/hyunsikjeong/0c26e83bb37866f5c7c6b8918a854333
https://github.com/josephsurin/lattice-based-cryptanalysis/blob/main/lbc_toolkit/problems/small_roots.sage
https://github.com/kionactf/coppersmith
https://eprint.iacr.org/2023/032.pdf
"""

from sage.all import *
from sage.rings.polynomial.multi_polynomial_sequence import PolynomialSequence
from Crypto.Util.number import getPrime
from tqdm import tqdm
import cysignals
import itertools
from re import sub as re_sub
from subprocess import run as subprocess_run
proof.all(False)

def _from_sagematrix_to_fplllmatrix(mat: matrix) -> str:
	return '[' + re_sub(
		r'\[ ',
		r'[',
		re_sub(r' +', r' ', str(mat))
	) + ']'

def _fplllmatrix_to_sagematrix(matrixstr: str) -> matrix:
	matlist = eval(matrixstr.replace(' ', ',').replace('\n', ','))
	return matrix(ZZ, matlist)

def _transformation_matrix(mat, lllmat, use_pari_matsol=False):
	# pari.matker() does not assure smallest kernel in Z (seems not call hermite normal form)
	# Sage kernel calls hermite normal form
	#
	# for computing ZZ transformation, use pari.matker, pari.matsolvemod
	# assume first kerdim vectors for lllmat are zero vector
	#
	# anyway, transformation computation after LLL/BKZ is slow.
	# instead, use builtin transformation computation on LLL/BKZ package

	if use_pari_matsol:
		mat_pari = pari.matrix(mat.nrows(), mat.ncols(), mat.list())
		ker_pari_t = pari.matker(pari.mattranspose(mat_pari), 1)
		kerdim = len(ker_pari_t)
		if kerdim == 0:
			# empty matrix
			trans = matrix(ZZ, 0, mat.nrows())
		else:
			trans = matrix(ZZ, pari.mattranspose(ker_pari_t).Col().list())

		mat_pari = pari.matrix(mat.nrows(), mat.ncols(), mat.list())
		for i in range(kerdim, lllmat.nrows(), 1):
			lllmat_pari = pari.vector(lllmat.ncols(), lllmat[i].list())
			trans_pari_t = pari.matsolvemod(
				pari.mattranspose(mat_pari), 0, pari.mattranspose(lllmat_pari)
			)
			transele = matrix(ZZ, trans_pari_t.mattranspose().Col().list())
			trans = trans.stack(transele)
	else:
		trans = mat.kernel().matrix()
		kerdim = trans.nrows()

		for i in range(kerdim, lllmat.nrows(), 1):
			transele = mat.solve_left(lllmat[i])
			trans = trans.stack(transele)

	return trans

def _do_LLL_flatter(
		mat: matrix,
		transformation: bool = False,
		use_pari_kernel: bool = False, use_pari_matsol: bool = False
	):


	if mat == zero_matrix(ZZ, mat.nrows(), mat.ncols()):
		return mat, identity_matrix(ZZ, mat.nrows())

	# sage has integer_kernel(), but somehow slow. instead using pari.matker
	if use_pari_kernel:
		mat_pari = pari.matrix(mat.nrows(), mat.ncols(), mat.list())
		ker_pari_t = pari.matker(mat_pari.mattranspose(), 1)
		ker = matrix(ZZ, ker_pari_t.mattranspose().Col().list())
	else:
		ker = mat.kernel().matrix()

	kerdim = ker.nrows()
	matrow = mat.nrows()
	col = mat.ncols()
	if kerdim == matrow: # full kernel
		return zero_matrix(ZZ, matrow, col), ker
	if kerdim == 0:
		Hsub = mat
		U = identity_matrix(ZZ, matrow)
	else:
		# heuristic construction for unimodular matrix which maps zero vectors on kernel
		# searching unimodular matrix can be done by HNF
		# (echeron_form(algorithm='pari') calls mathnf()),
		# but it is slow and produces big elements
		#
		# instead, searching determinant of submatrix = 1/-1,
		# then the determinant of whole unimodular matrix is det(submatrix)*(-1)^j
		# assume kernel has good property for gcd (gcd of some row elements might be 1)
		found_choice = False
		ker_submat_rows = tuple(range(kerdim))
		ker_submat_cols = []
		pivot = matrow - 1
		# search submatrix of kernel assuming last column vectors are triangulate
		while len(ker_submat_cols) < kerdim:
			if ker[ker_submat_rows, tuple([pivot])] != zero_matrix(ZZ, kerdim, 1):
				ker_submat_cols.append(pivot)
			pivot -= 1
		ker_submat_cols = tuple(sorted(ker_submat_cols))
		ker_last_det = int(ker[ker_submat_rows, ker_submat_cols].determinant())
		if ker_last_det == 0:
			raise ValueError("no unimodular matrix found (cause ker_last_det=0)")
		for choice in range(pivot, -1, -1):
			# gcd check
			gcd_row = ker_last_det
			for i in range(kerdim):
				gcd_row = GCD(gcd_row, ker[i, choice])
			if abs(gcd_row) != 1:
				continue

			# choice pivot: last columes for kernel are triangulated and small
			kersubidxes = [choice] + list(ker_submat_cols)
			detlst = [ker_last_det]
			for i in range(1, kerdim+1, 1):
				ker_submat_rows = tuple(range(kerdim))
				ker_submat_cols = tuple(kersubidxes[:i] + kersubidxes[i+1:])
				detlst.append(ker[ker_submat_rows, ker_submat_cols].determinant())
				detlist_gcd, detlist_coef = _xgcd_list(detlst)
				if detlist_gcd == 1:
					found_choice = True
					break
			if not found_choice:
				continue
			detlist_coef = detlist_coef + [0] * ((kerdim + 1) - len(detlist_coef))
			break
		if not found_choice:
			raise ValueError("no unimodular matrix found")
		U_top_vec = [0 for _ in range(matrow)]
		for i in range(kerdim+1):
			U_top_vec[kersubidxes[i]] = (-1)**i * detlist_coef[i]
		U_sub = matrix(ZZ, 1, matrow, U_top_vec)
		not_kersubidxes = sorted(list(set(list(range(matrow))) - set(kersubidxes)))
		for j in range(kerdim+1, matrow):
			onevec = [0 for _ in range(matrow)]
			onevec[not_kersubidxes[j-(kerdim+1)]] = 1
			U_sub = U_sub.stack(vector(ZZ, matrow, onevec))
		Hsub = U_sub * mat
		U = ker.stack(U_sub)
		#assert abs(U.determinant()) == 1

	if Hsub.nrows() == 1:
		lllmat = Hsub
	else:
		matstr = _from_sagematrix_to_fplllmatrix(Hsub)
		result = subprocess_run(
			'flatter',
			input=matstr.encode(), capture_output=True
		)
		if result.returncode != 0:
			print(result.stderr)
			raise ValueError(f"LLL failed with return code {result.returncode}")
		lllmat = _fplllmatrix_to_sagematrix(result.stdout.decode().strip())

	if transformation:
		trans = _transformation_matrix(Hsub, lllmat, use_pari_matsol=use_pari_matsol)
	else:
		trans = None

	restrows = mat.nrows() - lllmat.nrows()
	final_lllmat = zero_matrix(ZZ, restrows, lllmat.ncols()).stack(lllmat)

	if transformation:
		middle_trans = identity_matrix(ZZ, restrows).augment(zero_matrix(ZZ, restrows, trans.ncols())).stack(
			zero_matrix(ZZ, trans.nrows(), restrows).augment(trans)
		)
		final_trans = middle_trans * U
		#assert abs(final_trans.determinant()) == 1
		#assert final_trans * mat == final_lllmat
	else:
		final_trans = None

	return final_lllmat, final_trans

def coppersmith_generate_polynomial(N, _p):
	coefficients = []
	bounds = []
	i = 0
	ii = 0
	is_previous_unknown = True if _p[-1] == '?' else False

	for char in _p[::-1]:
		is_current_unknown = True if char == '?' else False
		if is_current_unknown and not is_previous_unknown:
			coefficients.append(2**(4*ii))
			i = 0
		if not is_current_unknown and is_previous_unknown:
			bounds.append(2**(4*i))
		is_previous_unknown = is_current_unknown
		i += 1
		ii += 1

	if is_current_unknown:
		bounds.append(2**(4*i))

	if _p[-1] == '?':
		coefficients = coefficients[::-1]
		coefficients.append(1)

	d = len(coefficients)
	xs = [f"x{i}" for i in range(d)]
	PR = PolynomialRing(Zmod(N), d, xs)
	f = int(_p.replace("?", "0"), 16) + sum([c * PR.objgens()[1][n] for n, c in enumerate(coefficients)])
	return f, bounds[::-1]

def coppersmith_univariate(f, X, beta=1.0, m=None):
	N = f.parent().characteristic()
	delta = f.degree()
	if m is None:
		epsilon = RR(beta**2/f.degree() - log(2*X, N))
		m = (max(beta**2/(delta * epsilon), 7*beta/delta)).ceil()
	t = int((delta*m*(1/beta - 1)).floor())
	#print(f"m = {m}")

	f = f.monic().change_ring(ZZ)
	P,(x,) = f.parent().objgens()
	g  = [x**j * N**(m-i) * f**i for i in range(m) for j in range(delta)]
	g.extend([x**i * f**m for i in range(t)])
	B = Matrix(ZZ, len(g), delta*m + max(delta,t))

	for i in range(B.nrows()):
		for j in range(g[i].degree()+1):
			B[i,j] = g[i][j]*X**j

	try:
		B, _ = _do_LLL_flatter(B)
	except:
		B = B.LLL()
	f = sum([ZZ(B[0,i]//X**i)*x**i for i in range(B.ncols())])
	roots = set([f.base_ring()(r) for r,m in f.roots() if abs(r) <= X])
	return [root for root in roots if N.gcd(ZZ(f(root))) >= N**beta]


def _solve_root_jacobian_newton_internal(pollst, startpnt, maxiternum=500):
	# NOTE: Newton method's complexity is larger than BFGS, but for small variables Newton method converges soon.
	pollst_Q = Sequence(pollst, pollst[0].parent().change_ring(QQ))
	vars_pol = pollst_Q[0].parent().gens()
	jac = jacobian(pollst_Q, vars_pol)

	if all([ele == 0 for ele in startpnt]):
		# just for prepnt != pnt
		prepnt = {vars_pol[i]: 1 for i in range(len(vars_pol))}
	else:
		prepnt = {vars_pol[i]: 0 for i in range(len(vars_pol))}
	pnt = {vars_pol[i]: startpnt[i] for i in range(len(vars_pol))}

	iternum = 0
	while True:
		if iternum >= maxiternum:
			return None

		evalpollst = [(pollst_Q[i].subs(pnt)) for i in range(len(pollst_Q))]
		if all([int(ele) == 0 for ele in evalpollst]):
			break
		jac_eval = jac.subs(pnt)
		evalpolvec = vector(QQ, len(evalpollst), evalpollst)
		try:
			pnt_diff_vec = jac_eval.solve_right(evalpolvec)
		except:
			return None

		prepnt = {key:value for key,value in prepnt.items()}
		pnt = {vars_pol[i]: int(pnt[vars_pol[i]] - pnt_diff_vec[i]) for i in range(len(pollst_Q))}
		if all([prepnt[vars_pol[i]] == pnt[vars_pol[i]] for i in range(len(vars_pol))]):
			return None
		prepnt = {key:value for key,value in pnt.items()}
		iternum += 1
	return [int(pnt[vars_pol[i]]) for i in range(len(vars_pol))]


def _solve_system_jacobian(pollst, bounds):
	vars_pol = pollst[0].parent().gens()
	# not applicable to non-determined system
	if len(vars_pol) > len(pollst):
		return []
	# pollst is not always algebraically independent,
	# so just randomly choose wishing to obtain an algebraically independent set
	for random_subset in tqdm(Combinations(pollst, k=len(vars_pol))):
		for signs in itertools.product([1, -1], repeat=len(vars_pol)):
			startpnt = [signs[i] * bounds[i] for i in range(len(vars_pol))]
			result = _solve_root_jacobian_newton_internal(random_subset, startpnt)
			# filter too much small solution
			if result is not None:
				if all([abs(ele) < 2**16 for ele in result]):
					continue
				return [result]

def _solve_system_gb(H, f, timeout=5):
	vs = list(f.variables())
	H_ = PolynomialSequence([], H[0].parent().change_ring(QQ))
	for h in tqdm(H):
		H_.append(h)
		I = H_.ideal()
		roots = []

		alarm(timeout)
		try:
			for root in I.variety(ring=ZZ):
				root = tuple(H[0].parent().base_ring()(root[var]) for var in vs)
				roots.append(root)
			cancel_alarm()
			if roots != []:
				return roots
		except:
			cancel_alarm()

class IIter:
	def __init__(self, m, n):
		self.m = m
		self.n = n
		self.arr = [0 for _ in range(n)]
		self.sum = 0
		self.stop = False

	def __iter__(self):
		return self

	def __next__(self):
		if self.stop:
			raise StopIteration
		ret = tuple(self.arr)
		self.stop = True
		for i in range(self.n - 1, -1, -1):
			if self.sum == self.m or self.arr[i] == self.m:
				self.sum -= self.arr[i]
				self.arr[i] = 0
				continue

			self.arr[i] += 1
			self.sum += 1
			self.stop = False
			break
		return ret

def _multivariate_herrmann_may(f, bounds, m, t):
	n = f.nvariables()
	N = f.base_ring().cardinality()
	f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)
	x = f.parent().objgens()[1]

	g = []
	monomials = []
	Xmul = []
	for ii in IIter(m, n):
		k = ii[0]
		g_tmp = f**k * N**max(t-k, 0)
		monomial = x[0]**k
		Xmul_tmp = bounds[0]**k
		for j in range(1, n):
			g_tmp *= x[j]**ii[j]
			monomial *= x[j]**ii[j]
			Xmul_tmp *= bounds[j]**ii[j]
		g.append(g_tmp)
		monomials.append(monomial)
		Xmul.append(Xmul_tmp)

	B = Matrix(ZZ, len(g), len(g))
	for i in range(B.nrows()):
		for j in range(i + 1):
			if j == 0:
				B[i, j] = g[i].constant_coefficient()
			else:
				v = g[i].monomial_coefficient(monomials[j])
				B[i, j] = v * Xmul[j]

	print("LLL...")
	try:
		B, _ = _do_LLL_flatter(B)
	except:
		B = B.LLL()
	print("LLL done")

	h = []
	for i in range(B.nrows()):
		h_tmp = 0
		for j in range(B.ncols()):
			if j == 0:
				h_tmp += B[i, j]
			else:
				assert B[i, j] % Xmul[j] == 0
				v = ZZ(B[i, j] // Xmul[j])
				h_tmp += v * monomials[j]
		h.append(h_tmp)

	return f, h

def _multivariate_shift_polynomials(f, bounds, m, d):
	if d is None:
		d = f.degree()

	R = f.base_ring()
	N = R.cardinality()
	f_ = (f // f.lc()).change_ring(ZZ)
	f = f.change_ring(ZZ)
	l = f.lm()

	M = []
	for k in range(m+1):
		M_k = set()
		T = set((f**(m-k)).monomials())
		for mon in (f**m).monomials():
			if mon//l**k in T:
				for extra in itertools.product(range(d), repeat=f.nvariables()):
					g = mon * prod(map(power, f.variables(), extra))
					M_k.add(g)
		M.append(M_k)
	M.append(set())

	shifts = PolynomialSequence([], f.parent())
	for k in range(m+1):
		for mon in M[k] - M[k+1]:
			g = mon//l**k * f_**k * N**(m-k)
			shifts.append(g)

	B, monomials = shifts.coefficients_monomials()
	monomials = vector(monomials)

	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	print("LLL...")
	try:
		B, _ = _do_LLL_flatter(B)
	except:
		B = B.dense_matrix().LLL()
	print("LLL done")

	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)
	B = B.change_ring(ZZ)

	H = PolynomialSequence([h for h in B*monomials if not h.is_zero()])
	return f, H

def coppersmith_multivariate(f, bounds, implementation, algorithm, m=1, t=1, d=None):
	if implementation == "herrmann_may":
		f, h = _multivariate_herrmann_may(f, bounds, m, t)
	elif implementation == "shift_polynomials":
		f, h = _multivariate_shift_polynomials(f, bounds, m, d)
	else:
		print("invalid implementation")
		return None

	if algorithm == "jacobian":
		return _solve_system_jacobian(h, bounds)
	elif algorithm == "groebner":
		return _solve_system_gb(h, f)
	else:
		print("invalid algorithm")
		return None

# MSBs of p are given
def coppersmith_rsa_recover_p_high(p_high, n, p_bits):
	p_high_bits = len(bin(p_high)) - 2
	x = Zmod(n)['X'].gen()
	f = p_high * 2**(p_bits-p_high_bits) + x
	x = coppersmith_univariate(f, X=2**(p_bits-p_high_bits), beta=0.4)
	if x == []:
		return None
	p = int(f(x[0]))
	if is_prime(p):
		return p
	return None

# LSBs of p are given
def coppersmith_rsa_recover_p_low(p_low, n, p_bits):
	p_low_bits = len(bin(p_low)) - 2
	x = Zmod(n)['X'].gen()
	f = x * 2**p_low_bits + p_low
	x = coppersmith_univariate(f, X=2**(p_bits-p_low_bits), beta=0.4)
	if x == []:
		return None
	p = int(f(x[0]))
	if is_prime(p):
		return p
	return None

def demo_1():
	p = getPrime(512)
	q = getPrime(512)
	n = p*q
	p_high = int(hex(p)[:100], 16)
	print("\ndemo 1: p_high")
	if coppersmith_rsa_recover_p_high(p_high, n, 512) is not None:
		print("PASS")
	else:
		print("FAIL")

def demo_2():
	p = getPrime(512)
	q = getPrime(512)
	n = p*q
	p_low = int(hex(p)[-100:], 16)
	print("\ndemo 2: p_low")
	if coppersmith_rsa_recover_p_low(p_low, n, 512) is not None:
		print("PASS")
	else:
		print("FAIL")

def demo_3():
	def recover_d_low(d_low, n, e, p_bits):
		t = len(bin(d_low)) - 2
		for k in tqdm(range(1, e)):
			x = var('x')
			for r in solve_mod([x*e*d_low == x + k*(n*x - x**2 - n + x)], 2**t):
				p_low = int(r[0])
				try:
					p = coppersmith_rsa_recover_p_low(p_low, n, p_bits)
					if p is not None and is_prime(p):
						return p
				except:
					continue

	while True:
		p = getPrime(256)
		q = getPrime(256)
		e = 11
		n = p*q
		try:
			d = int(pow(e, -1, (p-1)*(q-1)))
			break
		except ZeroDivisionError:
			continue

	d_low = int(hex(d)[80:], 16)
	print("\ndemo 3: d_low")
	if recover_d_low(d_low, n, e, 256) is not None:
		print("PASS")
	else:
		print("FAIL")

def demo_4():
	def recover_dp_high(dp_high, n, e):
		beta = 0.4
		upper_bound = int(2*n**(beta**2))
		dp_bits_max = (len(bin(n))-2)//2
		for dp_bits in range(dp_bits_max + 1, dp_bits_max - 20, -1):
			_dp = int(dp_high * 2**(dp_bits - (len(bin(dp_high))-2)))
			for xi in range(-upper_bound + upper_bound//8, upper_bound, upper_bound//4):
				x = Zmod(n)['X'].gen()
				f = _dp*e + x - xi
				x = f.small_roots(X=upper_bound, beta=beta)
				if x == []:
					continue
				kp = int(f(x[0]))
				p = gcd(n, kp)
				if 1 < p < n and is_prime(p):
					return p

	p = getPrime(512)
	q = getPrime(512)
	n = p*q
	e = 65537
	d = pow(e, -1, (p-1)*(q-1))
	dp = int(d % (p-1))
	dp_high = int(hex(dp)[:100], 16)
	print("\ndemo 4: dp_high")
	if recover_dp_high(dp_high, n, e) is not None:
		print("PASS")
	else:
		print("FAIL")

def demo_5():
	n = 0x7de3efa8914a53819b254c1fbd8c899e48484df13ee28ebcaa8ae55d979b683ab38a462a716bf54ff5982ab1152269ba920ffdc5e037ebda4685ad734cab9048a851f811624b01d102e1f1623f226101ffdedd78a3e90779f41911ba5d29e7b643e9934ad391d5b68ad3c71d4999d197e73d7f1320073627928d12190fcc9207427d497f4bf1802592e53302d47c8a9eb45f6488515bb6d14baf223dc73d5b11d75f3d483857797ac406ab062e8ceb17767da6c360ffdd304f058518f80374a9ee806675fb89e5399693d3a199e2786efe3b19f8b7f3804df332a1c036f3e4025ef0b9bed9e3963513ad3e8092f4f71ce91e5149cffe1a585ffd95599fce75f5
	p = 0xa2f51e080856a2737bb2357dabcb6b5dba7d03cf0ecf0cf378b47666227cb3a0da901b6de823d8be53c401895f0a4ba24c47bd243039d6bd1f51890f06ba0b9ce75b73d4fe86ee047ba422cfbca474e2c70170097498fd9db8ce21f5c1ce1ec1f22a48569ff794066fc4d53f67a5583b5f605ee12192af5e690178e79d61d257
	_p = "?????????????????????????????????????????????????????????????????????????????????????1895f0a4ba24c47bd243039d6bd1f51890f06ba0b9ce75b73d4fe86ee047ba422cfbca474e2c70170097498fd9db8ce21f5c1ce1ec1f22a48569ff794066fc4d53f67a5583b5f605ee12192af5e690178e79d61d257"
	f, bounds = coppersmith_generate_polynomial(n, _p)
	print("\ndemo 5: one chunk")
	print(coppersmith_multivariate(f, bounds, implementation="herrmann_may", algorithm="groebner", m=2))
	print(coppersmith_multivariate(f, bounds, implementation="herrmann_may", algorithm="jacobian", m=2))
	print(coppersmith_multivariate(f, bounds, implementation="shift_polynomials", algorithm="groebner", m=1, d=2))
	print(coppersmith_multivariate(f, bounds, implementation="shift_polynomials", algorithm="jacobian", m=1, d=2))

def demo_6():
	n = 0x7de3efa8914a53819b254c1fbd8c899e48484df13ee28ebcaa8ae55d979b683ab38a462a716bf54ff5982ab1152269ba920ffdc5e037ebda4685ad734cab9048a851f811624b01d102e1f1623f226101ffdedd78a3e90779f41911ba5d29e7b643e9934ad391d5b68ad3c71d4999d197e73d7f1320073627928d12190fcc9207427d497f4bf1802592e53302d47c8a9eb45f6488515bb6d14baf223dc73d5b11d75f3d483857797ac406ab062e8ceb17767da6c360ffdd304f058518f80374a9ee806675fb89e5399693d3a199e2786efe3b19f8b7f3804df332a1c036f3e4025ef0b9bed9e3963513ad3e8092f4f71ce91e5149cffe1a585ffd95599fce75f5
	p = 0xa2f51e080856a2737bb2357dabcb6b5dba7d03cf0ecf0cf378b47666227cb3a0da901b6de823d8be53c401895f0a4ba24c47bd243039d6bd1f51890f06ba0b9ce75b73d4fe86ee047ba422cfbca474e2c70170097498fd9db8ce21f5c1ce1ec1f22a48569ff794066fc4d53f67a5583b5f605ee12192af5e690178e79d61d257
	_p = "a2f51e080856a2737bb2357dabcb6b5dba7d03cf0ecf0cf378b47666227cb3a0da901b6de823d8be53c401895f0a4ba24c47bd243039d6bd1f51890f06ba0b9ce75b73d4fe86ee047ba422cfbca474e2c7017009749?????????????????????????????????????????????????????????????????????????????????????"
	f, bounds = coppersmith_generate_polynomial(n, _p)
	print("\ndemo 6: one chunk")
	print(coppersmith_multivariate(f, bounds, implementation="herrmann_may", algorithm="groebner", m=2))
	print(coppersmith_multivariate(f, bounds, implementation="herrmann_may", algorithm="jacobian", m=2))
	print(coppersmith_multivariate(f, bounds, implementation="shift_polynomials", algorithm="groebner", m=1, d=2))
	print(coppersmith_multivariate(f, bounds, implementation="shift_polynomials", algorithm="jacobian", m=1, d=2))

def demo_7():
	n = 0x7de3efa8914a53819b254c1fbd8c899e48484df13ee28ebcaa8ae55d979b683ab38a462a716bf54ff5982ab1152269ba920ffdc5e037ebda4685ad734cab9048a851f811624b01d102e1f1623f226101ffdedd78a3e90779f41911ba5d29e7b643e9934ad391d5b68ad3c71d4999d197e73d7f1320073627928d12190fcc9207427d497f4bf1802592e53302d47c8a9eb45f6488515bb6d14baf223dc73d5b11d75f3d483857797ac406ab062e8ceb17767da6c360ffdd304f058518f80374a9ee806675fb89e5399693d3a199e2786efe3b19f8b7f3804df332a1c036f3e4025ef0b9bed9e3963513ad3e8092f4f71ce91e5149cffe1a585ffd95599fce75f5
	p = 0xa2f51e080856a2737bb2357dabcb6b5dba7d03cf0ecf0cf378b47666227cb3a0da901b6de823d8be53c401895f0a4ba24c47bd243039d6bd1f51890f06ba0b9ce75b73d4fe86ee047ba422cfbca474e2c70170097498fd9db8ce21f5c1ce1ec1f22a48569ff794066fc4d53f67a5583b5f605ee12192af5e690178e79d61d257
	_p = "a2f51e080856a2737bb2357dabcb6b5dba7d03cf0ecf0cf378b47666227cb3a0da901b6de823d8be53c401895f0?????????????????????????????????????????????????????????????????????????????????fd9db8ce21f5c1ce1ec1f22a48569ff794066fc4d53f67a5583b5f605ee12192af5e690178e79d61d257"
	f, bounds = coppersmith_generate_polynomial(n, _p)
	print("\ndemo 7: one chunk")
	print(coppersmith_multivariate(f, bounds, implementation="herrmann_may", algorithm="groebner", m=2))
	print(coppersmith_multivariate(f, bounds, implementation="herrmann_may", algorithm="jacobian", m=2))
	print(coppersmith_multivariate(f, bounds, implementation="shift_polynomials", algorithm="groebner", m=1, d=2))
	print(coppersmith_multivariate(f, bounds, implementation="shift_polynomials", algorithm="jacobian", m=1, d=2))

def demo_8():
	n = 0x7de3efa8914a53819b254c1fbd8c899e48484df13ee28ebcaa8ae55d979b683ab38a462a716bf54ff5982ab1152269ba920ffdc5e037ebda4685ad734cab9048a851f811624b01d102e1f1623f226101ffdedd78a3e90779f41911ba5d29e7b643e9934ad391d5b68ad3c71d4999d197e73d7f1320073627928d12190fcc9207427d497f4bf1802592e53302d47c8a9eb45f6488515bb6d14baf223dc73d5b11d75f3d483857797ac406ab062e8ceb17767da6c360ffdd304f058518f80374a9ee806675fb89e5399693d3a199e2786efe3b19f8b7f3804df332a1c036f3e4025ef0b9bed9e3963513ad3e8092f4f71ce91e5149cffe1a585ffd95599fce75f5
	p = 0xa2f51e080856a2737bb2357dabcb6b5dba7d03cf0ecf0cf378b47666227cb3a0da901b6de823d8be53c401895f0a4ba24c47bd243039d6bd1f51890f06ba0b9ce75b73d4fe86ee047ba422cfbca474e2c70170097498fd9db8ce21f5c1ce1ec1f22a48569ff794066fc4d53f67a5583b5f605ee12192af5e690178e79d61d257
	_p = "a2f51e080856a2737bb2357dabcb6b5dba7d03cf0ecf0cf378b47666227cb3a0da901b6de823d8be53c401895f0a4ba24c47bd????????????????????????????????????86ee047ba422cfbca474e2c70170097498fd9db8ce21f5c1ce1ec1f22a48569ff794066fc4d53f67a5583b5f6?????????????????????????????"
	f, bounds = coppersmith_generate_polynomial(n, _p)
	print("\ndemo 8: two chunks")
	print(coppersmith_multivariate(f, bounds, implementation="herrmann_may", algorithm="jacobian", m=5))
	print(coppersmith_multivariate(f, bounds, implementation="shift_polynomials", algorithm="jacobian", m=2, d=4))

def demo_9():
	n = 0x7de3efa8914a53819b254c1fbd8c899e48484df13ee28ebcaa8ae55d979b683ab38a462a716bf54ff5982ab1152269ba920ffdc5e037ebda4685ad734cab9048a851f811624b01d102e1f1623f226101ffdedd78a3e90779f41911ba5d29e7b643e9934ad391d5b68ad3c71d4999d197e73d7f1320073627928d12190fcc9207427d497f4bf1802592e53302d47c8a9eb45f6488515bb6d14baf223dc73d5b11d75f3d483857797ac406ab062e8ceb17767da6c360ffdd304f058518f80374a9ee806675fb89e5399693d3a199e2786efe3b19f8b7f3804df332a1c036f3e4025ef0b9bed9e3963513ad3e8092f4f71ce91e5149cffe1a585ffd95599fce75f5
	p = 0xa2f51e080856a2737bb2357dabcb6b5dba7d03cf0ecf0cf378b47666227cb3a0da901b6de823d8be53c401895f0a4ba24c47bd243039d6bd1f51890f06ba0b9ce75b73d4fe86ee047ba422cfbca474e2c70170097498fd9db8ce21f5c1ce1ec1f22a48569ff794066fc4d53f67a5583b5f605ee12192af5e690178e79d61d257
	_p = "a2f51e080856a2737bb2357dabcb6b5dba7d03cf0ecf0cf378b47666227cb3a0da901b6de823d8be53c401895f0a4ba24c4????????????d1f51890f06ba0b9ce75b73d4fe86ee047ba422cfbca474e2c70170097498fd9db8ce21????????????2a48569ff794066fc4d53f67a5583b5f605ee12192af5e690178e79d61d257"
	f, bounds = coppersmith_generate_polynomial(n, _p)
	print("\ndemo 9: two chunks")
	print(coppersmith_multivariate(f, bounds, implementation="herrmann_may", algorithm="groebner", m=2))
	print(coppersmith_multivariate(f, bounds, implementation="herrmann_may", algorithm="jacobian", m=2))
	print(coppersmith_multivariate(f, bounds, implementation="shift_polynomials", algorithm="jacobian", m=1, d=4))

def demo_10():
	n = 0x7de3efa8914a53819b254c1fbd8c899e48484df13ee28ebcaa8ae55d979b683ab38a462a716bf54ff5982ab1152269ba920ffdc5e037ebda4685ad734cab9048a851f811624b01d102e1f1623f226101ffdedd78a3e90779f41911ba5d29e7b643e9934ad391d5b68ad3c71d4999d197e73d7f1320073627928d12190fcc9207427d497f4bf1802592e53302d47c8a9eb45f6488515bb6d14baf223dc73d5b11d75f3d483857797ac406ab062e8ceb17767da6c360ffdd304f058518f80374a9ee806675fb89e5399693d3a199e2786efe3b19f8b7f3804df332a1c036f3e4025ef0b9bed9e3963513ad3e8092f4f71ce91e5149cffe1a585ffd95599fce75f5
	p = 0xa2f51e080856a2737bb2357dabcb6b5dba7d03cf0ecf0cf378b47666227cb3a0da901b6de823d8be53c401895f0a4ba24c47bd243039d6bd1f51890f06ba0b9ce75b73d4fe86ee047ba422cfbca474e2c70170097498fd9db8ce21f5c1ce1ec1f22a48569ff794066fc4d53f67a5583b5f605ee12192af5e690178e79d61d257
	_p = "????????????????7bb2357dabcb6b5dba7d03cf0ecf0cf378b47666227cb3a0da901b6de823d8be53c401895f0a4ba24c47bd243039d6bd1f51890f06ba0????????????????e047ba422cfbca474e2c70170097498fd9db8ce21f5c1ce1ec1f22a48569ff794066fc4d53f67a5583b5f605ee12192af5e????????????????"
	f, bounds = coppersmith_generate_polynomial(n, _p)
	print("\ndemo 10: three chunks")
	print(coppersmith_multivariate(f, bounds, implementation="herrmann_may", algorithm="jacobian", m=5))

def main():
	demo_1()
	demo_2()
	demo_3()
	demo_4()
	demo_5()
	demo_6()
	demo_7()
	demo_8()
	demo_9()
	demo_10()

if __name__ == "__main__":
	main()
