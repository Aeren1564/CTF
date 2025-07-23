from CTF_Library import *

output = [
	"afe4dfec75d05b8204f949749dce9d69eaee982528f7e2c177862b4f12b635d9",
	"6d04f0ebde78ca72c0a65629cd6f2cc337319c05b266ed789843ea2bdf11551f",
	"61483d050ad72a0e6dda11e3f683fbac20ab17b4a26615ac3eb4fbaecef519bd",
	"13c9395628b7f90ff1675d73cc97ae24ea5c9993366364627d20f9f52b19fabb",
	"75e04f3f38420029fa57934de57b6fb59f9615e4be32eaa4460c57a47c2842ae",
]

p = int(output[0], 16)
F = GF(p)
R = F['X']
x = R.gen()
coef = list(map(lambda x: F(int(x, 16)), output[1:5]))

c0 = coef[0] * coef[1] / coef[3]
c1 = coef[1] / coef[0] / coef[2]

r = (c0 / c1).sqrt()
for a, _ in (c1 * x**2 - 2 * c0 * c1 * x + c0).roots():
	for b, _ in ((c0 * c1 - 1) * x**2 + (2 * c0 - 2 * c0**2 * c1) * x - c0**2).roots():
		if a in F and b in F:
			flag = long_to_bytes(int(a), 32) + long_to_bytes(int(b), 32)
			if flag.startswith(b"ictf{") and flag.endswith(b"}"):
				print(flag)
