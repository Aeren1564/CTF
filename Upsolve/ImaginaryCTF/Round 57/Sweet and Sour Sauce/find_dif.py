x = "scpghm"
y = "scheme"
dif = []
for c, d in zip(x, y):
	dif += [ord(d) - ord(c)]
print(dif)