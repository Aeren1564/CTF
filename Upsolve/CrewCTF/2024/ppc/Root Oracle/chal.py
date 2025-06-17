import secrets

Numqueries=13000

def secretshuffle(per):
	for i in range(1,len(per)):
		pos=secrets.randbelow(i)
		per[pos],per[i]=per[i],per[pos]
	return per

def ok(x,n):
	return not (x<0 or x>n-1)

def numroots(a,b,c):
	delta=b*b-4*a*c
	if delta<0:
		return 0
	if delta==0:
		return 1
	if delta>0:
		return 2

def execute_level(x):
	print(f"=============== LEVEL {x} ===============")
	n=100+x*100
	print(f"n={n}")
	per=[i+1 for i in range(n)]
	per=secretshuffle(per)
	for t in range(Numqueries):
		x,y,z=map(int,input().split(","))
		if x==-1 and y==-1 and z==-1:
			#ready to guess
			break
		if (not ok(x,n)) or (not ok(y,n)) or (not ok(z,n)):
			print("Bad input!")
			exit(0)
		print(f"roots={numroots(per[x],per[y],per[z])}")
	per2=[int(x) for x in input().split(",")]
	if len(per2)!=n:
		print("Bad permutation!")
		exit(0)
	
	for i in range(n):
		if per2[i]!=per[i]:
			print("Wrong permutation!")
			exit(0)
	print("Correct permutation!")

for i in range(5):
	execute_level(i)
	execute_level(i)

FLAG=open("flag","r").read()
print(FLAG)
