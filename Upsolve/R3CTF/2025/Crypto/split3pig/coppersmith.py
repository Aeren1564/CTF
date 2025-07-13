from sage.all import *
# from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
from subprocess import run as subprocess_run
from re import findall

# proof.all(False)
flatter_path = "/usr/local/bin/"
def flatter(M):
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = subprocess_run(flatter_path + "flatter", input=z.encode(), cwd=flatter_path, capture_output=True)
    if ret.returncode != 0:
        print(ret.stderr)
        raise ValueError(f"LLL failed with return code {ret.returncode}")
    ret = ret.stdout
    return matrix(ZZ, M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))
# set_verbose(2)

def poly_sub(f, x, y):
    ret = f.parent().zero()
    for c, m in f:
        
        while m % x == 0:
            m //= x
            c *= y
        ret += c * m

    return ret

def f_crt(ms, vs):
    ps = prod(ms)
    f = 0
    for i in range(len(ms)):
        v = ps // ms[i]
        f += vs[i] * v * pow(v, -1, ms[i])
    return f

def gen_momonial_set(h_s):
    monomial_set = set()
    for h in h_s:
        monomial_set = monomial_set.union(h.monomials())
    return sorted(monomial_set)

def gen_matrix_from_poly(h_s, X):
    monomial_set = gen_momonial_set(h_s)
    # print(f'{monomial_set = }')
    mat = [[0 for _ in range(len(monomial_set))] for __ in range(len(h_s))]
    W = [monomial.subs(X) for monomial in monomial_set]
    for i in range(len(h_s)):
        mat[i] = [h_s[i].monomial_coefficient(monomial) for monomial in monomial_set]

    W = diagonal_matrix(ZZ, W, sparse = False)
    return matrix(ZZ, mat), W, monomial_set
    
def coppersmith_univariate(f, X, beta = 1.0, m = 1, t = 0):
    f_zz = f.change_ring(ZZ)
    x = f_zz.variables()[0]
    P_ZZ = PolynomialRing(ZZ, x)
    
    ZmodN = f.base_ring()
    N = ZmodN.characteristic()
    delta = f.degree()
    # f_zz_lst = [f_zz ** i for i in range(m + 1)]
    # Ns = [N ** (m - i) for i in range(m + 1)]
    # xs = [x ** i for i in range(t)]
    fs = []
    for i in range(m):
        for j in range(delta):
            h_ij = x ** j * N ** (m - i) * f_zz ** i
            fs.append(h_ij)
            # h_ij = 
            # fs.append(xs[j] * Ns[i] * f_zz_lst[i])
    for i in range(t):
        # fs.append(xs[i] * f_zz_lst[m])
        fs.append(x ** i * f_zz ** m)
        
    mat, W, monomials = gen_matrix_from_poly(fs, X)
    W = diagonal_matrix(ZZ, [m.subs(X) for m in monomials], sparse = False)
    mat = mat.change_ring(ZZ)
    # print(mat.dimensions(), mat.parent())
    # print(W.parent())
    # print(W.is_diagonal())
    mat *= W
    mat = flatter(mat)
    # print('Done LLL')
    # mat = mat.LLL()
    mat /= W
    
    roots = set()
    for row in mat:
        g = P_ZZ(row.list())
        rs = set([x[0] for x in g.roots() if x[0] < X])
        roots = roots.union(rs)
    roots = [ZmodN(r) for r in roots]
    Nbeta = int(ZZ(N) ** RR(beta))
    print(f'{roots = }')
    # print([gcd(f(r), N) for r in roots])
    return [root for root in roots if gcd(f(root), N) >= Nbeta]

def coppersmith_multivariate(f, X, beta = 1.0, m = 1, t = 0):
    f_zz = f.change_ring(ZZ)
    vs = f_zz.variables()
    assert(len(X) == len(vs)), "Mismatch length of bounds and vars"
    P_ZZ = PolynomialRing(ZZ, vs)
    
    ZmodN = f.base_ring()
    N = ZmodN.characteristic()
    delta = f.degree()
    
    fs = []
            
    for i in range(m + 1):
        for j in range(delta):
            h_ij = x ** j * N ** (m - i) * f_zz ** i
            fs.append(h_ij)
    for i in range(t):
        fs.append(x ** i * f_zz ** m)
    
    print(f'{X = }')
    
    mat, monomials = Sequence(fs, P_ZZ).coefficients_monomials()
    monomials = vector(P_ZZ, monomials)
    # exit()
    W = diagonal_matrix(ZZ, [m(*X) for m in monomials], sparse = False)
    
    print(mat.dimensions())
    mat *= W
    mat = flatter(mat)
    mat /= W
    
    roots = set()
    fs = []
    for row in mat:
        fs.append(monomials * row)

    Nbeta = int(ZZ(N) ** RR(beta))
    return [root for root in roots if gcd(f(root), N) >= Nbeta]

def boneh_durfee(f, X, m = 1, t = 1):
    f_zz = f.change_ring(ZZ)
    x, y = f_zz.variables()
    P_ZZ = PolynomialRing(ZZ, (x, y))
    
    ZmodN = f.base_ring()
    N = ZmodN.characteristic()
    # delta = f.degree()
    
    fs = []
    for k in range(m + 1):
        for i in range(m - k + 1):
            g_ik = x ** i * N ** (m - k) * f_zz ** k
            fs.append(g_ik)
        for i in range(t + 1):
            fs.append(y ** i * N ** (m - k) * f_zz ** k)
        
    
    mat, monomials = Sequence(fs, P_ZZ).coefficients_monomials()
    monomials = vector(P_ZZ, monomials)
    W = diagonal_matrix(ZZ, [m(*X) for m in monomials], sparse = False)
    
    print(mat.dimensions())
    mat *= W
    mat = flatter(mat)
    mat /= W
    
    roots = set()
    for row in mat:
        g = P_ZZ(row.list())
        rs = set([x[0] for x in g.roots() if x[0] < X])
        roots = roots.union(rs)
    roots = [ZmodN(r) for r in roots]
    Nbeta = int(ZZ(N) ** RR(beta))
    return [root for root in roots if gcd(f(root), N) >= Nbeta]

def wiener_general(N, e, X, beta = 1.0):
    M = N + 1 - 2 * isqrt(N)
    P = PolynomialRing(Zmod(M), 'x, y')
    x, y = P.gens()
    f = e * x + y
    f_zz = f.change_ring(ZZ)
    P_ZZ = PolynomialRing(ZZ, (x, y))
    x, y = P_ZZ.gens()
    
    fs = [M * x, f_zz]
    mat, monomials = Sequence(fs, P_ZZ).coefficients_monomials()
    monomials = vector(P_ZZ, monomials)
    W = diagonal_matrix(ZZ, [m(*X) for m in monomials], sparse = False)

    mat *= W
    mat = flatter(mat)
    mat /= W
    
    y0, x0 = mat[0, :].list()
    y0, x0 = int(abs(y0)), int(abs(x0))
    return x0, y0

def wiener_lattice(N, e, X):
    P = PolynomialRing(Zmod(N), 'x, y')
    x, y = P.gens()
    f = e * x + y
    f_zz = f.change_ring(ZZ)
    P_ZZ = PolynomialRing(ZZ, (x, y))
    x, y = P_ZZ.gens()
    
    fs = [N * x, f_zz]
    mat, monomials = Sequence(fs, P_ZZ).coefficients_monomials()
    monomials = vector(P_ZZ, monomials)
    W = diagonal_matrix(ZZ, [m(*X) for m in monomials], sparse = False)

    mat *= W
    mat = flatter(mat)
    mat /= W
    
    y0, x0 = mat[0, :].list()
    y0, x0 = int(abs(y0)), int(abs(x0))
    return x0, y0

def crt_list_decoding(B, v, m):
    P = prod(m)
    R = crt(v, m)
    d = 30
    a = 20
    a_prime = d - a
    gs, hs = [], []
    PR = PolynomialRing(ZZ, 'x')
    x = PR.gen(0)
    for i in range(a):
        gs.append(P ** (a - i) * (x - R) ** i)
    for i in range(a_prime):
        hs.append(x ** i * (x - R) ** a)
    mat, W, monomials = gen_matrix_from_poly(gs + hs, B)
    # for row in mat:
        # print(row)
    print(mat.dimensions())
    mat *= W
    mat = flatter(mat)
    print('Done LLL')
    # mat = mat.LLL()
    mat /= W
    
    roots = set()
    for row in mat:
        g = PR(row.list())
        rs = set([x for x in g.roots(multiplicities = False)])
        roots = roots.union(rs)
    roots = list(roots)
    print(f'{roots = }')
    return roots