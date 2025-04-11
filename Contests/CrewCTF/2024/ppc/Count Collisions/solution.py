from pwn import *

nc = remote("count-collisions.chal.crewc.tf", 1337)
#nc = process(["python3", "server.py"])

print(nc.recvline())
print(nc.recvline())

n = 100

def cnt(Hash):
	tot_sum, adj_and = Hash[0], Hash[1 : n]
	adj_and = [tot_sum - x >> 1 for x in adj_and]
	dp = [[0] * n for _ in range(n + 1)]
	dp[0][0] = 1
	for i in range(n):
		for c in range(n):
			dp2 = [[[0] * (2 * n) for _ in range(2)] for _ in range(n)]
			dp2[0][0][c] = dp[i][c]
			dp2[0][1][c + 1] = dp[i][c]
			for j in range(n - 1):
				for b in range(2):
					for d in range(2 * n):
						if not dp2[j][b][d]:
							continue
						for b_next in range(2):
							if (b & b_next) != (adj_and[j] >> i & 1):
								continue
							dp2[j + 1][b_next][d + b_next] += dp2[j][b][d]
			for b in range(2):
				for d in range(2 * n):
					if (d & 1) != (tot_sum >> i & 1):
						continue
					dp[i + 1][d >> 1] += dp2[n - 1][b][d]
	return dp[n][tot_sum >> n]

for tc_num in range(10):
	print(f"{tc_num = }")
	print(nc.recvline())
	Hash = eval(nc.recvline().strip())
	print(f"{Hash = }")
	x = cnt(Hash)
	print(f"sending {x = }")
	nc.sendline(str(x).encode())
	resp = nc.recvline().strip()
	print(resp)
	print()
	assert resp == b"Correct!"
print(nc.recvline())
print(nc.recvline())