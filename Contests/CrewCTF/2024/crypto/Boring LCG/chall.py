import os
from sage.all import *

set_random_seed(1337)
p = 18315300953692143461
Fp, z = GF(p**3, 'z').objgen()
a, b = Fp.random_element(), Fp.random_element()

os.environ["flag"] = "crew{TEST_FLAG?++zzz????WOW!}"
flag = (os.getenv('flag') or 'crew{submit_this_if_desperate}').encode()
print(f"{flag = }")
s = Fp.from_integer(int.from_bytes(flag[len('crew{'):-len('}')], 'big'))
print(f"{s = }")

out = []
for _ in range(12): out.extend(s:=a*s+b)
print([x>>57 for x in out])
# [50, 32, 83, 12, 49, 34, 81, 101, 46, 108, 106, 57, 105, 115, 102, 51, 67, 34, 124, 15, 125, 117, 51, 124, 38, 10, 30, 76, 125, 27, 89, 14, 50, 93, 88, 56]