from Crypto.Cipher import AES
def AES_decrypt(ciphertext: bytes, key: bytes, iv: bytes = None, mode = AES.MODE_ECB):
	assert len(ciphertext) % 16 == 0
	assert len(key) == 16
	assert len(iv) == 16
	assert mode == AES.MODE_ECB and iv == None or mode != AES.MODE_ECB and iv != None
	return AES.new(key, mode, iv).decrypt(ciphertext)