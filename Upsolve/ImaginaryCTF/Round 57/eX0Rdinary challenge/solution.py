from CTF_Library import *

cipher = base64.b64decode("FAoXEh0PHAEaLDYaLD4+LwIXEQANJiwHERcXChsNCRUBOycXHS08CwkNADM9FwErPg8XDhYYCiw4CAALOzUFDT03CRcTOj4+OQoNBho=")

key = [ord('}')]
flag = []
for i, c in enumerate(cipher):
	flag.append(key[i] ^ c)
	key.append(flag[-1])
print(bytes(flag))
