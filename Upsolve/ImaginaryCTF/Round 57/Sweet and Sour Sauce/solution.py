from CTF_Library import *

enc_flag = "jcex{ie_bjda_jlgt_kiej_eemv_dt_ia_ytbrmayuep_wkg_iah_biefglj_sopghm}"
shift = [-1, 0, 15, 8, 0, -12, -8, -2, 5, -8, 13, -4, 20, 0, 9]
i = 0
flag = ""
for c in enc_flag:
	if not c.isalpha():
		flag += c
		continue
	flag += chr(ord('a') + (ord(c) - ord('a') + shift[i]) % 26)
	i = (i + 1) % len(shift)
print(flag)
