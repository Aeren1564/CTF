from Crypto.Util.number import getPrime, getRandomNBitInteger, isPrime
from sage.all import *
import hashlib
import threading
def worker(idx, lb, ub, fs, n, m, t):
    print(f'Thread {idx} running with bitlength ({lb}, {ub})')
    for q_bit in range(lb, ub):
        print(f'{q_bit = }')
        bound = q_bit - k.bit_length() + 2
        beta = QQ(q_bit * 2) / 2607 - 0.03
        print(f'{bound = }, {beta = }')
        bound = 2 ** bound
        for f in fs:        
            roots = coppersmith_univariate(f, bound, beta, m = m, t = t)
            if len(roots) == 0:
                continue
            print(f'{roots = }')
            print(f'{v = }')
            q2 = gcd(int(f(roots[0])), n)
            q = int(sqrt(q2))
            p = n // (q ** 2)
            print(n % p, n % q)
            print(f'{p = }')
            H = hashlib.sha256()    
            H.update(str(q).encode())
            flag = "r3ctf{" + H.hexdigest() + "}"
            print(f'Flag: {flag}')
            exit()

from coppersmith import *

n = 39857078746406469131129281921490520306196739933449401384580614683236877901453146754149222509812535866333862501431453065249306959004319408436548574942416212329735258587670686655658056553446879680643872518009328886406310298097685861873954727153720761248262606469217940464611561028443119183464419610396387619860313813067179519809796028310723320608528262638653826016645983671026819244220510314301178181698134390850683834304169240632402535087021483298892547974104858755498823118164815682452718215716370727477136888839954993949013970026988378086175471190518276414200966496353144747778470590767485019943178534397845127421058830430797806265311195099187747227867325234593386438995618936934586514932401108874934000734850169069717060963988677462779177959990601405850727404268354600078746523164279
E1 = 17599828213549223253832044274649684283770977196846184512551517947600728059 
E2 = 13524024408490227176018717697716068955892095093578246398907145843636542721

k = E1 * E2

P = PolynomialRing(Zmod(n), 'x')
x = P.gen()

v2s = [int(crt([int(q_e2), 1], [E1, E2])) for q_e2 in Mod(n, E1).nth_root(2, all = True)]
fs = [((v2 + x * k) ** 2).monic() for v2 in v2s]
m = 8
t = 4

ts = []
for i in range(4):
    thr = threading.Thread(target=worker, args=(i, 800 + i * 15, 800 + (i + 1) * 15, fs, n, m, t))
    ts.append(thr)
    thr.start()

for t in ts:
    t.join()  
