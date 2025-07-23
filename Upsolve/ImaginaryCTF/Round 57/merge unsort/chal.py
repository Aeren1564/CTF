from secrets import randbits
from Crypto.Random.random import shuffle
from Crypto.Util.number import bytes_to_long

def merge_sort(arr, cmp=lambda x, y: x < y):
	if len(arr) <= 1:
		return arr
	mid = len(arr) // 2
	left = merge_sort(arr[:mid], cmp)
	right = merge_sort(arr[mid:], cmp)
	return sorted_merge(left, right, cmp)

def sorted_merge(a, b, cmp):
	res = []
	while a and b:
		res.append(a.pop(0) if cmp(a[0], b[0]) else b.pop(0))
	return res + a + b

def f(x,y):
	return randbits(1)



def truth(count = 200):
	out = []
	l = [_ for _ in range(n)]
	for i in range(count):
		shuffle(l)
		out.append(l[:])
	return out

def fraud(count = 200):
	l = [_ for _ in range(n)]
	out = [merge_sort(l,f) for _ in range(count)]
	return out


	


flag = b'ictf{REDACTED}'

encoded = bin(bytes_to_long(flag))[2:]
encoded = (8 - len(encoded) % 8) * '0' + encoded
n = 5

output = []
for i in encoded:
	if (i == '1'):
		output.append(fraud())
	else:
		output.append(truth())
print(output)