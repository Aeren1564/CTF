from hints import hints
from testcases import Edges
#from mycase import Edges
from Crypto.Hash import SHA1

tc_cnt = len(hints)
print(f"{tc_cnt = }")

def solve_tc(tc_num, hint, inp):
	n, edges = inp
	adj = [[] for _ in range(n)]
	for u, v in edges:
		adj[u].append(v)
		adj[v].append(u)
	print(f"{tc_num = }")
	print(f"{n = }")
	print(f"{len(edges) = }")
	def generate_isometry(cube):
		assert len(set(cube)) == 8
		cube2 = tuple([x for x in cube])
		isometry = []
		for _0 in range(2):
			for _1 in range(4):
				for _2 in range(3):
					isometry.append(tuple([x for x in cube2]))
					cube2 = (cube2[0], cube2[3], cube2[7], cube2[4], cube2[1], cube2[2], cube2[6], cube2[5])
				cube2 = (cube2[1], cube2[2], cube2[3], cube2[0], cube2[5], cube2[6], cube2[7], cube2[4])
			cube2 = (cube2[6], cube2[5], cube2[4], cube2[7], cube2[2], cube2[1], cube2[0], cube2[3])
		return isometry
	def generate_adj_cube(cube):
		assert len(set(cube)) == len(cube)
		cube2 = tuple([x for x in cube])
		adj_cube = []
		for _0 in range(2):
			for _1 in range(3):
				d = [c[cube2[0]][i] - c[cube2[4]][i] for i in range(3)]
				for u in adj[cube2[0]]:
					if u == cube2[4]:
						continue
					for v in adj[cube2[3]]:
						if v in adj[u]:
							for w in adj[cube2[2]]:
								if w in adj[v]:
									for x in adj[cube2[1]]:
										if x in adj[w] and u in adj[x]:
											cube3 = (cube2[0], cube2[3], cube2[2], cube2[1], u, v, w, x)
											if len(set(cube3)) != 8:
												continue
											c[u] = [c[cube2[0]][i] + d[i] for i in range(3)]
											c[v] = [c[cube2[3]][i] + d[i] for i in range(3)]
											c[w] = [c[cube2[2]][i] + d[i] for i in range(3)]
											c[x] = [c[cube2[1]][i] + d[i] for i in range(3)]
											adj_cube.append(tuple([x for x in cube3]))
				cube2 = (cube2[0], cube2[3], cube2[7], cube2[4], cube2[1], cube2[2], cube2[6], cube2[5])
			cube2 = (cube2[6], cube2[5], cube2[4], cube2[7], cube2[2], cube2[1], cube2[0], cube2[3])
		return adj_cube
	c = [(None, None, None)] * n
	q = []
	cube_set = set()
	def init():
		for u in range(n):
			for v in adj[u]:
				for w in adj[v]:
					for x in adj[w]:
						if u in adj[x]:
							for uu in adj[u]:
								for vv in adj[v]:
									if vv in adj[uu]:
										for ww in adj[w]:
											if ww in adj[vv]:
												for xx in adj[x]:
													if xx in adj[ww] and uu in adj[xx]:
														cube = (u, v, w, x, uu, vv, ww, xx)
														if len(set(cube)) != 8:
															continue
														c[u] = (0, 0, 0)
														c[v] = (1, 0, 0)
														c[w] = (1, 1, 0)
														c[x] = (0, 1, 0)
														c[uu] = (0, 0, 1)
														c[vv] = (1, 0, 1)
														c[ww] = (1, 1, 1)
														c[xx] = (0, 1, 1)
														q.append(cube)
														for iso_cube in generate_isometry(cube):
															cube_set.add(iso_cube)
														return
	init()
	qi = 0
	while qi < len(q):
		cube, qi = q[qi], qi + 1
		if qi % 1000 == 0:
			print(f"#{qi}, {cube = }")
		for cube2 in generate_adj_cube(cube):
			if cube2 in cube_set:
				continue
			for iso_cube2 in generate_isometry(cube2):
				cube_set.add(iso_cube2)
			q.append(cube2)
	for u in range(n):
		for i in range(3):
			assert c[u][i] != None
	def finalize():
		side = 40
		def check_hint(vis):
			h = SHA1.new()
			st = []
			for i in range(side):
				for j in range(side):
					for k in range(side):
						st.append(str(int(vis[i][j][k])))
			h.update("".join(st).encode())
			print(f"{h.digest() = }")
			print(f"{hint = }")
			print()
			return h.digest() == hint
		def check():
			vis = [[[False] * side for _ in range(side)] for _ in range(side)]
			base = [min([c[u][i] for u in range(n)]) for i in range(3)]
			for u in range(n):
				for i in range(3):
					assert base[i] <= c[u][i] and c[u][i] <= base[i] + side
			for cube in cube_set:
				rep = [min(c[u][i] for u in cube) - base[i] for i in range(3)]
				vis[rep[0]][rep[1]][rep[2]] = True
			if check_hint(vis):
				return vis
			else:
				return None
		for _0 in range(2):
			for _1 in range(2):
				for _2 in range(3):
					for _3 in range(4):
						print(f"Trying {_0 = }, {_1 = }, {_2 = }, {_3 = }")
						vis = check()
						if vis:
							return vis
						for u in range(n):
							c[u] = [-c[u][1], c[u][0], c[u][2]]
					for u in range(n):
						c[u] = [c[u][1], c[u][2], c[u][0]]
				for u in range(n):
					c[u] = [-c[u][1], -c[u][0], -c[u][2]]
			for u in range(n):
				c[u][0] = -c[u][0]
		return None
	vis = finalize()
	assert vis
	return vis
with open("answer.py", 'w') as f:
	f.write(f"solutions = []\n")
	f.close()
for tc_num, (hint, inp) in enumerate(zip(hints, Edges)):
	vis = solve_tc(tc_num, hint, inp)
	with open("answer.py", 'a') as f:
		f.write(f"solutions.append({vis})\n")
		f.close()