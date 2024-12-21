# # Source: https://toadstyle.org/cryptopals/63.txt
# # Note: it returns CTR_key(b'0' * 128)
# class GCM_attack_for_repeated_nonce:
# 	# Assume that the same 128-bit key and 96-bit nonce has been used to encrypt the data with bitlength <= 128, along with the tag generation
# 	def __init__(self, nonce: bytes, ct0: bytes, tag0: bytes, ad0: bytes, ct1: bytes, tag1: bytes, ad1: bytes):
# 		assert len(nonce) == 12
# 		from sage.all import GF, polygen, factor
# 		from Crypto.Util.number import bytes_to_long, long_to_bytes
# 		x = GF(2)['x'].gen()
# 		F = GF(2**128, name = 'a', modulus = 1 + x + x**2 + x**7 + x**128)
# 		x = polygen(F)
# 		poly = []
# 		for ct, tag, ad in [(ct0[:], tag0[:], ad0[:]), (ct1[:], tag1[:], ad1[:])]:
# 			print(f"{ct = }, {tag = }, {ad = }")
# 			len_block = len(ad) * 8 + len(ct) * 8 * 64
# 			ad += '0' * ((16 - len(ad) % 16) % 16)
# 			ct += '0' * ((16 - len(ct) % 16) % 16)
# 			print(f"{ct = }, {tag = }, {ad = }")
# 			cur_poly = 0
# 			for i in range(0, len(ad), 16):
# 				cur_poly = cur_poly * x + F.fetch_int(bytes_to_long(ad[i : i + 16]))
# 			print(f"{cur_poly = }")
# 			for i in range(0, len(ct), 16):
# 				cur_poly = cur_poly * x + F.fetch_int(bytes_to_long(ct[i : i + 16]))
# 			print(f"{cur_poly = }")
# 			cur_poly = cur_poly * x + F.fetch_int(len_block)
# 			cur_poly = cur_poly * x + F.fetch_int(bytes_to_long(tag))
# 			poly.append(cur_poly)
# 			print(f"{cur_poly = }")
# 		keyhashs = []
# 		for fact, _ in factor(poly[0] + poly[1]):
# 			if fact.degree() == 1:
# 				print(f"{fact = }")
# 				keyhashs.append(long_to_bytes(fact[0].to_integer()))
# 		return keyhashs
# 	def encrypt_and_digest(plaintext: bytes, ad: bytes, ):

