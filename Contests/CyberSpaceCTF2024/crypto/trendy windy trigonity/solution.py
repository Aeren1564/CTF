from CTF_Library import *
from Crypto.Util.number import *

R = RealField(1000)
x = R(75872961153339387563860550178464795474547887323678173252494265684893323654606628651427151866818730100357590296863274236719073684620030717141521941211167282170567424114270941542016135979438271439047194028943997508126389603529160316379547558098144713802870753946485296790294770557302303874143106908193100) / 10**len("75872961153339387563860550178464795474547887323678173252494265684893323654606628651427151866818730100357590296863274236719073684620030717141521941211167282170567424114270941542016135979438271439047194028943997508126389603529160316379547558098144713802870753946485296790294770557302303874143106908193100")

scale = 10**300
enc = 278332652222000091147933689155414792020338527644698903976732528036823470890155538913578083110732846416012108159157421703264608723649277363079905992717518852564589901390988865009495918051490722972227485851595410047572144567706501150041757189923387228097603575500648300998275877439215112961273516978501 * 10**46
c = int(cos(x) * scale)
s = int(sin(x) * scale)

mat = [
	[1, 0, 0, c],
	[0, 1, 0, s],
	[0, 0, 1, -enc]
]
lowerbound = [0, 0, 1, 0]
upperbound = [2**(19 * 8), 2**(19 * 8), 1, 0]

vec = solve_inequality_with_CVP(mat, lowerbound, upperbound)
print(f"{vec = }")
print(int(vec[0]).to_bytes(19) + int(vec[1]).to_bytes(19))