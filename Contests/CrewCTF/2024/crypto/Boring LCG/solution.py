from CTF_Library import *
from itertools import chain
import copy

set_random_seed(1337)

p = 18315300953692143461
F = FiniteField(p**3, 'z')
a, b = F.random_element(), F.random_element()