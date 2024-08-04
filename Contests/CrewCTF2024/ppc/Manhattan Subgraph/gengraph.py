import random

def gengraph(n, vis):
	#vis is a n x n x n array of booleans representing whether the cube at position (i,j,k) is painted or not
	#the graph is formed by the following way
	#for every pair of adjacent vertices (manhattan distance one), we connect an edge if it is an edge of a painted cube
	#then we permute the vertices of this graph, so as to create a isomorphic graph
	D=set({})
	for x in range(n):
		for y in range(n):
			for z in range(n):
				if vis[x][y][z]:
					for x1 in range(0,2):
						for y1 in range(0,2):
							for z1 in range(0,2):
								pos=(x+x1)*(n+1)*(n+1)+(y+y1)*(n+1)+(z+z1)
								for i in range(0,3):
									if i==0:
										pos2=(x+(x1^1))*(n+1)*(n+1)+(y+y1)*(n+1)+(z+z1)
										if pos<pos2:
											D.add((pos,pos2))
									if i==1:
										pos2=(x+x1)*(n+1)*(n+1)+(y+(y1^1))*(n+1)+(z+z1)
										if pos<pos2:
											D.add((pos,pos2))
									if i==2:
										pos2=(x+x1)*(n+1)*(n+1)+(y+y1)*(n+1)+(z+(z1^1))
										if pos<pos2:
											D.add((pos,pos2))
								
	
	#relabel and permute the graph
	Idx=dict({})
	for a in D:
		for b in a:
			if b not in Idx:
				Idx[b]=len(Idx)
	per=[i for i in range(len(Idx))]
	random.shuffle(per)
	D2=[]
	for a in D:
		D2.append((per[Idx[a[0]]],per[Idx[a[1]]]))
	return (len(per),D2)

n = 3
vis = [
	[[False, False, False], [False, True, False], [False, False, False]],
	[[False, True, False], [True, True, True], [False, True, False]],
	[[False, False, False], [False, True, False], [False, False, False]]
]
print(gengraph(n, vis))