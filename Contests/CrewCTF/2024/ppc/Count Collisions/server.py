import secrets
import itertools

FLAG="crew{TEST_FLAG??!@#???_!!}"
def genHash(V):
	Hash=[]
	for i in range(len(V)):
		Value=0
		for j in range(len(V)):
			if j==i and j>0:
				Value-=V[j-1]
				Value+=(V[j]^V[j-1])
			else:
				Value+=V[j]
		Hash.append(Value)
	return Hash

n, m = 100, 100

"""
I swear in my computer this runs very fast
Trust me
"""
def cntcollisions(Hsh):
	P=itertools.product(*[range(pow(2,m))] * n)
	cnt=0
	for a in P:
		cnt+=(genHash(a)==Hsh)
	return cnt


print("I bet you can't count the number of collisions of this Hash!")

for T in range(10):
	print("How many collisions?:")
	msg=[secrets.randbelow(pow(2,m)) for i in range(n)]
	Hash=genHash(msg)
	print(Hash)

	cntUser=int(input())
	x = cntcollisions(Hash)
	if cntcollisions(Hash)==cntUser:
		print("Correct!")
	else:
		print("Nope!", x)
		exit(0)

print("You found a flag!")
print(FLAG)
