from CTF_Library import *
from make_flag import render
from tree_store import get_chunks
from base64 import b64encode

base = set()
for _ in range(5000):
	pool = string.ascii_letters + string.digits + "_"
	n = random.randint(0, 32)
	flag = "bctf{"
	for _ in range(n):
		flag += random.choice(pool)
	flag += "}"
	render(flag)
	with open("flag.bmp", "rb") as f:
		flag_bytes = f.read()
	size_before = len(base)
	for chunk in get_chunks(flag_bytes):
		base.add(chunk)

print(f"initial {len(base) = }")

io = remote("challs.pwnoh.io", 13420)

capacity = 0
pending_query_cnt = 0
resp_i = 0
resp_q = []

def get_resp():
	global io
	io.readuntil(b">>> ")
	resp = io.readlineS().strip()
	assert resp != "[-] Max storage exceeded!"
	return resp

def present_in_db_query(m : bytes):
	global io, pending_query_cnt, capacity, resp_i, resp_q
	pending_query_cnt += 1
	capacity += len(m)
	if capacity > 2**21:
		while pending_query_cnt > 1:
			pending_query_cnt -= 1
			resp_q.append(get_resp())
		io.close()
		io = remote("challs.pwnoh.io", 13420)
		pending_query_cnt = 1
		capacity = len(m)
		io.readlinesS(2)
	io.sendline(b64encode(m))

def present_in_db_resp():
	global io, pending_query_cnt, capacity, resp_i, resp_q
	if resp_i < len(resp_q):
		resp, resp_i = resp_q[resp_i], resp_i + 1
	else:
		pending_query_cnt -= 1
		resp = get_resp()
	resp = int(resp.split(" ")[0])
	return resp == 0

io.readlinesS(2)
for chunk in base:
	present_in_db_query(chunk)
base = [chunk for chunk in base if present_in_db_resp()]
history = base[:]

for width in range(1, 1000):
	n = 16 << width - 1
	print(f"{n = }")
	print(f"{len(base) = }")
	print(f"{len(history) = }")
	print(f"{len(base[0]) = }")
	for x in base:
		if len(x) == n:
			for y in history:
				present_in_db_query(x + y)
	base_next = [x + y for x in base if len(x) == n for y in history if present_in_db_resp()]
	if len(base_next) == 0:
		break
	base = list(set(base_next))
	history.extend(base)

assert len(base) == 1
res = base[0]

print(f"FINAL")
print(f"{res = }")
with open("flag.bmp", "wb") as f:
	f.write(res)
