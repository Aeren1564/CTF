from Crypto.Cipher import AES
import base64

ct = "OGIyUmRFajMxcGpjYm94ZC9uK3pPQUFBQUFBQUFBQUFBQUFBQUFBQUFBQT0="

ct = base64.b64decode(ct)

print(ct)