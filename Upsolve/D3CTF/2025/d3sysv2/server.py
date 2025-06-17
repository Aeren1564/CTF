from Crypto.Util.number import bytes_to_long, getPrime, inverse
from hashlib import sha256
from secret import FLAG
import socketserver
import signal 
import os
 

banner = br"""
 _ .-') _                               .-') _               
( (  OO) )                             (  OO) )              
 \     .'_   ,---.   .-----.    .-----./     '._    ,------. 
 ,`'--..._) /  \  \ /  -.   \  '  .--./|'--...__)('-| _.---' 
 |  |  \  '`--' `--''-' _'  |  |  |('-.'--.  .--'(OO|(_\     
 |  |   ' |            |_  <  /_) |OO  )  |  |   /  |  '--.  
 |  |   / :         .-.  |  | ||  |`-'|   |  |   \_)|  .--'  
 |  '--'  /         \ `-'   /(_'  '--'\   |  |     \|  |_)   
 `-------'           `----''    `-----'   `--'      `--'     
				   .-----.   .----.   .-----. .------.       
				  / ,-.   \ /  ..  \ / ,-.   \|   ___|       
				  '-'  |  |.  /  \  .'-'  |  ||  '--.        
					 .'  / |  |  '  |   .'  / `---.  '.      
				   .'  /__ '  \  /  ' .'  /__ .-   |  |      
				  |       | \  `'  / |       || `-'   /      
				  `-------'  `---''  `-------' `----''       
"""


MENU2 = br'''
 ====------------------------------------------------------------------------------------------------------====
 |    |              +---------------------------------------------------------------------+              |   |
 |    |              |            [G]et_dp_dq     [F]lag     [T]ime     [E]xit             |              |   |
 |    |              +---------------------------------------------------------------------+              |   |
 ====------------------------------------------------------------------------------------------------------====
'''

class CRT_RSA_SYSTEM:
	nbit = 3072
	blind_bit = 153
	unknownbit = 983
	e_bit = 170

	def __init__(self):
		e = getPrime(self.e_bit)
		p,q = [getPrime(self.nbit // 2) for _ in "D^3CTF"[:2]]
		n = p * q
		self.pub = (n,e)

		dp = inverse(e,p - 1)
		dq = inverse(e,q - 1)
		self.priv = (p,q,dp,dq,e,n)
		self.blind()

	def blind(self):
		p,q,dp,dq,e,n = self.priv
		rp,rq = [getPrime(self.blind_bit) for _ in "D^3CTF"[:2]]
		dp_ = (p-1) * rp + dp
		dq_ = (q-1) * rq + dq
		self.priv = (p,q,dp_,dq_,e,n)

	def get_priv_exp(self):
		p,q,dp,dq,e,n = self.priv
		dp_ = dp >> self.unknownbit
		dq_ = dq >> self.unknownbit
		return (dp_,dq_)

	def encrypt(self,m):
		n,e = self.pub
		return pow(m,e,n)

	def decrypt(self,c):
		p,q,dp,dq,e,n = self.priv
		mp = pow(c,dp,p)
		mq = pow(c,dq,q)
		h = inverse(q, p) * (mp - mq) % p
		m = mq + h * q
		# m = crt([mp,mq],[p,q])
		assert pow(m,e,n) == c
		return m

class D3_SYS(socketserver.BaseRequestHandler):
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

	def recv(self, prompt=b''):
		self.send(prompt, newline=False)
		return self._recvall()

	def get_dp_dq(self):
		return self.crt_rsa.get_priv_exp()

	def enc_token(self):
		token = os.urandom(380) 
		n,e = self.crt_rsa.pub
		enc_token = pow(bytes_to_long(token),e,n)
		return enc_token, sha256(token).hexdigest()

	def handle(self):
		signal.alarm(5)
		self.send(banner)
		self.send(b"Welcome to D^3CTF 2025")
		self.send(b"Hello player... This year I give you a new challenge which is similar as the second part in d3sys[D^3CTF 2023].")
		self.crt_rsa = CRT_RSA_SYSTEM()
		for __ in 'D^3CTF'[:2]:
			self.send(MENU2)
			option = self.recv(b'option >')
			if option == b'F':
				cip,tokenhash = self.enc_token()
				self.send(b'Encrypted Token: ' + hex(cip).encode())
				tokenhash_checked = self.recv(b'Token Hash: ')
				if tokenhash_checked.decode() == tokenhash:
					self.send(b'Correct!')
					self.send(FLAG.encode())
				else:
					self.send(b'Wrong Token Hash!')
			elif option == b'G':
				dp,dq = self.get_dp_dq()
				self.send(f'dp,dq:{[dp,dq]}'.encode())
				self.send(f'n,e:{[self.crt_rsa.pub]}'.encode())
			elif option == b'T':
				pass # self.time()
			else:
				break
		self.request.close()

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
	pass

if __name__ == "__main__":
	HOST, PORT = '0.0.0.0', 10001
	print("HOST:POST " + HOST+":" + str(PORT))
	server = ForkedServer((HOST, PORT), D3_SYS)
	server.allow_reuse_address = True
	server.serve_forever()