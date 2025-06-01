#!/usr/bin/env python3
from Crypto.Util.number import getPrime
from hashlib import sha256
from secret import FLAG
import socketserver
import signal
import random
import string
import os


BANNER = br"""
	____ //|_____    __________________   ___   ____ ___   ______
   / __ \/||__  /   / ____/_  __/ ____/  |__ \ / __ \__ \ / ____/
  / / / /   /_ <   / /     / / / /_      __/ // / / /_/ //___ \  
 / /_/ /  ___/ /  / /___  / / / __/     / __// /_/ / __/____/ /  
/_____/  /____/   \____/ /_/ /_/       /____/\____/____/_____/   
"""


MENU = br"""
1. Get p
2. H4sh
3. Flag
4. Exit
"""


class FNV():
	def __init__(self):
		self.pbit = 1024
		self.p = getPrime(self.pbit)
		self.key = random.randint(0, self.p)
	
	def H4sh(self, value:str):
		length = len(value)
		x = (ord(value[0]) << 7) % self.p
		for c in value:
			x = ((self.key * x) % self.p) ^ ord(c)
		
		x ^= length
		
		return x


class Task(socketserver.BaseRequestHandler):
	def _recvall(self):
		BUFF_SIZE = 2048
		data = b''
		while True:
			part = self.request.recv(BUFF_SIZE)
			data += part
			if len(part) < BUFF_SIZE:
				break
		return data.strip()

	def send(self, msg, newline=True):
		try:
			if newline:
				msg += b'\n'
			self.request.sendall(msg)
		except:
			pass

	def recv(self, prompt=b'> '):
		self.send(prompt, newline=False)
		return self._recvall()

	def close(self):
		self.send(b"Bye~")
		self.request.close()

	def handle(self):
		signal.alarm(30)

		self.send(BANNER)
		
		n = 32
		cnt = 67
		str_table = string.ascii_letters + string.digits
		self.send(b'Welcome to D^3CTF 2025')
		self.send(b'Could you break my modified fnv hash function?')
		self.fnv = FNV()
		
		for _ in range(cnt):
			self.send(MENU)
			option = self.recv(b'option >')
			if option == b'G':
				p = self.fnv.p
				self.send(f'p = {p}'.encode())
			
			elif option == b'H':
				random_token = ''.join(random.choices(str_table, k=n))
				random_token_hash = self.fnv.H4sh(random_token)
				self.send(b'Token Hash: ' + str(random_token_hash).encode())
			
			elif option == b'F':
				random_token = ''.join(random.choices(str_table, k=n))
				self.send(b'Here is a random token x: ' + random_token.encode())
				ans = self.recv(b'Could you tell the value of H4sh(x)? ').strip().decode()
				if int(ans) % self.fnv.p == self.fnv.H4sh(random_token) % self.fnv.p:
					self.send(b'Congratulations! Here is your flag: ')
					self.send(FLAG)
				else:
					self.send(b'Try again~')
			
			else:
				break
		
		self.close()


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	pass


class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
	pass


if __name__ == "__main__":
	HOST, PORT = '0.0.0.0', 10007
	server = ForkedServer((HOST, PORT), Task)
	server.allow_reuse_address = True
	server.serve_forever()