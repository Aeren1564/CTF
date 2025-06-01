from sage.all import *
from random import randint , shuffle
import hashlib
from Crypto.Util.number import *
from Crypto.Cipher import AES
from flag import flag
p = 2**1105 - 1335
k = 99
n = 24
alpha = 2

GFp = GF(p)
def pad(m):
    return m + (16-(len(m)%16))*bytes([16-(len(m)%16)])
def genmatrix(x , y):
    M = random_matrix(ZZ , n , n , x = x , y = y+1)
    M = Matrix(GFp , M)
    while M.rank()!=n:
        M = random_matrix(ZZ , n , n , x = x , y = y+1)
        M = Matrix(GFp , M)
    return M
def keygen():
    Alist = []
    for i in range(k):
        A = genmatrix(0 , alpha)
        Alist.append(A)
    D = genmatrix(0 , alpha)

    E = random_matrix(GFp , n , n)
    while E.rank() != n:
        E = random_matrix(GFp , n , n)

    E_1 = E**(-1)
    _Alist = []
    for i in range(k):
        _A = E * Alist[i]*D *E_1
        _Alist.append(_A)
    return _Alist , (E , D , Alist)

def enc(pk , m):
    rangelist = list(range(k))
    shuffle(rangelist)
    c = pk[rangelist[0]]
    for i in range(k-1):
        c *= pk[rangelist[i+1]]

    key = hashlib.sha256(str(rangelist).encode()).digest()
    aes = AES.new(key = key , mode = AES.MODE_ECB)
    flagc = aes.encrypt(pad(m))
    return c , flagc
pk , sk = keygen()
save(pk ,"pk.sobj")
c , flagc = enc(pk , flag)

save(c , "c.sobj")
print(flagc)
#b'lD\xfc\xf4\xdb+\xcd\xbd\xff\x1a!C\x0e\x16\t\xa7:<\x94<\xac(M(i\xee\xf9B\xc7\xea}\x1b\x86\xf8e\xff\xa8<\xc2\xf0\x02P\xd8%$\xc3\xe9-'