from math import log2, ceil
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
ω = 19103219067921713944291392827692070036145651957329286315305642004821462161904
k = 14
ω = pow(ω, 2**(28-k), p)
assert pow(ω, 2**k, p) == 1
expansion_factor = 256
λ = 64
s = 8
class Params:
    def __init__(self):
        self.p = p
        self.ω = ω
        self.k = k
        self.expansion_factor = expansion_factor
        self.λ = λ
        self.domain_length = 2**k
        self.r = ceil(log2(self.domain_length // expansion_factor))
        self.s = s

    def __repr__(self):
        return (f"Params(p={self.p}, ω={self.ω}, k={self.k}, "
                f"expansion_factor={self.expansion_factor}, s={self.s})")    

    def _set(self, object):
        for key in ["p", "ω", "k", "expansion_factor", "s", "domain_length", "r"]:
            setattr(object, key, getattr(self, key))

params = Params()

domain = [pow(ω, i, p) for i in range(params.domain_length)]