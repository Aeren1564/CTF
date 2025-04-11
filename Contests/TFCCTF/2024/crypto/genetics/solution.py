from itertools import permutations

ct = "CCCA CACG CAAT CAAT CCCA CACG CTGT ATAC CCTT CTCT ATAC CGTA CGTA CCTT CGCT ATAT CTCA CCTT CTCA CGGA ATAC CTAT CCTT ATCA CTAT CCTT ATCA CCTT CTCA ATCA CTCA CTCA ATAA ATAA CCTT CCCG ATAT CTAG CTGC CCTT CTAT ATAA ATAA CGTG CTTC"
pool = "ACTG"
base = [0, 1, 2, 3]
for value in permutations(base):
	mapping = {}
	for i in range(4):
		mapping[pool[i]] = value[i]
	a = []
	for x in ct.split(" "):
		a.append(4**3 * mapping[x[0]] + 4**2 * mapping[x[1]] + 4 * mapping[x[2]] + mapping[x[3]])
	print(bytes(a))