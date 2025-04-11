
with open('out.txt', 'r') as f:
	ct = eval(f.read())

print(len(ct))
for i in range(len(ct)):
	print(len(ct[i]))