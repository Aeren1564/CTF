from CTF_Library import *

from out import output

enc_flag = ""
for data in output:
	if sum(1 if max(a[0], a[1]) <= 1 else 0 for a in data) <= 30:
		enc_flag += '0'
	else:
		enc_flag += '1'
print(long_to_bytes(int(enc_flag, 2)))
