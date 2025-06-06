

# This file was *autogenerated* from the file main.sage
from sage.all_cmdline import *   # import sage library

_sage_const_5 = Integer(5); _sage_const_10 = Integer(10); _sage_const_1 = Integer(1); _sage_const_3 = Integer(3); _sage_const_2 = Integer(2); _sage_const_32 = Integer(32); _sage_const_127 = Integer(127); _sage_const_0 = Integer(0)
from random import shuffle
from tqdm import tqdm, trange
proof.all(False)

flag = b'idek{REDACTED}'

n  = randint(_sage_const_5 , _sage_const_10 )
print('n =', n)
Sn = SymmetricGroup(n)
gs = [Sn.random_element() for _ in range(randint(_sage_const_1 , _sage_const_3 ))]
print('Selected random generators!')
print('gs =', gs)

G = PermutationGroup(gs)
n = G.cardinality()
print('#G =', n)

p = random_prime(_sage_const_2 **_sage_const_32 , lbound=_sage_const_127 )
F = GF(p)
print('p =', p)

irr = gap.IrreducibleRepresentations(G)
rep = irr[randint(_sage_const_2 , int(irr.Length()))]
print('Generated rep!')
print(rep)

G = rep.Image()
reps = [
    matrix(F,r)
    for r in tqdm(G.Enumerator())
    if r != G.One() # It would be too easy :)
]
print('Computed image of G!')
print(f"{reps = }")

n = int(G.One().Length())
print(f"one length {n = }")
flag += bytes( (n - len(flag)) % n )


res = []
for i in trange(_sage_const_0 , len(flag), n):
    λ = F.random_element()
    v = λ * vector(F, flag[i:i+n])
    res.append([
        tuple(r*v)
        for r in reps
        if  not r.is_one()
    ])
    shuffle(res[-_sage_const_1 ])
print('Computed image of flag!')

# with open('out.txt', 'w') as file:
#     file.write(str(res))
with open('myout.txt', 'w') as file:
    file.write(str(res))

