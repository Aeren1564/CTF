from CTF_Library import *

N = 7314115252283636608283909725370457727076563580799920315154071960840699660519829311181093122148272777913745382460410854655175915612132848738615987055676619
F = GF(N)
flag_share_id = 1337
forbidden_share_id = 20984567098134765
no_secret = b'no secret here...'

def id_to_bytes(n):
	return hashlib.sha3_512(int(n).to_bytes(512, 'little')).digest()

def decrypt(key_n: int, ct: bytes):
	key = id_to_bytes(int(key_n))[:32]
	nonce = ct[:12]
	cipher = AES.new(key, mode = AES.MODE_CTR, nonce = nonce)
	return cipher.decrypt(ct[12:])

id_count = 6
id_list = [flag_share_id, forbidden_share_id] + list(range(1, id_count - 1))
assert len(id_list) == id_count
print(f"{id_list = }")
#with process(["python3", "server.py"]) as io:
with remote("pss.atreides.b01lersc.tf", 8443, ssl = True) as io:
	def read_share():
		json_data = json.loads(io.readlineS().strip())
		return list(map(F, json_data["padded_shares"])), list(map(bytes.fromhex, json_data["secret_ct"]))
	def read_provision():
		json_data = json.loads(io.readlineS().strip())
		return list(map(F, json_data["pads"]))
	def get_share(share_id: int):
		assert share_id not in [flag_share_id, forbidden_share_id]
		io.sendlineafter(b">> ", b"1")
		io.sendlineafter(b">> ", str(share_id).encode())
		io.readline()
		return read_share()
	def get_provision(share_ids):
		io.sendlineafter(b">> ", b"2")
		for share_id in share_ids:
			io.sendlineafter(b">> ", str(share_id).encode())
		io.readline()
		return read_provision()
	def get_lagrange_coefficients(x):
		assert len(x) == 5 and len(set(x)) == 5
		coefs = []
		for i in range(5):
			c = F(1)
			for j in range(5):
				if i == j:
					continue
				c *= F(-x[j]) / F(x[i] - x[j])
			coefs.append(c)
		return coefs[:]
	def shared_var_id(share_id, index):
		assert share_id in id_list and 0 <= index < 5
		return id_list.index(share_id) * 5 + index
	def secret_var_id(share_id, index):
		assert share_id in id_list and 0 <= index < 5
		return id_count * 5 + id_list.index(share_id) * 5 + index
	def poly_var_id(index, deg):
		assert 0 <= index < 5 and 0 <= deg < 5
		return id_count * 10 + index * 5 + deg
	var_count = id_count * 10 + 25
	io.readline()
	flag_padded_shares, flag_secret_ct = read_share()
	mat = []
	vec = []
	for index in range(5):
		eq_coef = [F(0) for _ in range(var_count)]
		for d in range(5):
			eq_coef[poly_var_id(index, d)] = F(flag_share_id)**d
		eq_coef[shared_var_id(flag_share_id, index)] = F(-1)
		mat.append(eq_coef[:])
		vec.append(flag_padded_shares[index])
	for share_id in id_list:
		if share_id in [flag_share_id, forbidden_share_id]:
			continue
		data = get_share(share_id)[0]
		for index in range(5):
			eq_coef = [F(0) for _ in range(var_count)]
			for d in range(5):
				eq_coef[poly_var_id(index, d)] = F(share_id)**d
			eq_coef[shared_var_id(share_id, index)] = F(-1)
			mat.append(eq_coef[:])
			vec.append(data[index])
	for init_subset in itertools.combinations(range(id_count), 5):
		if 0 in init_subset and 1 not in init_subset:
			continue
		print(f"{init_subset = }")
		subset = list(init_subset)
		for _ in range(5):
			print(f"{subset = }")
			lag_coef = get_lagrange_coefficients([id_list[i] for i in subset])
			data = get_provision([id_list[i] for i in subset])
			for index in range(5):
				eq_coef = [F(0) for _ in range(var_count)]
				for i in range(5):
					eq_coef[shared_var_id(id_list[subset[i]], index)] = lag_coef[i]
					eq_coef[secret_var_id(id_list[subset[index]], index)] = F(1)
				mat.append(eq_coef[:])
				vec.append(data[index])
			subset = subset[1:] + subset[:1]
		print()
	res = matrix(F, mat).solve_right(vector(F, vec))
	for index in range(5):
		flag = decrypt(res[poly_var_id(index, 0)] + res[secret_var_id(flag_share_id, index)], flag_secret_ct[index])
		if b"bctf{" in flag:
			print(f"{flag}")
			exit(0)
	print()
