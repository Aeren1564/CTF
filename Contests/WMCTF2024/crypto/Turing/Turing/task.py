from hashlib import sha256
import socketserver
import signal
import string
import random
import os
from string import ascii_uppercase
from random import shuffle, choice, randint
from pyenigma import *
from myenigma import myReflector, myrotors

flag = 


def check(s1, s2):
    if len(s1) != len(s2):
        return False
    count = 0
    for i in range(len(s1)):
        if s1[i] == s2[i]:
            count += 1
    if (count/len(s1)) > 0.85:
        return True
    return False


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

    def recv(self, prompt=b'[-] '):
        self.send(prompt, newline=False)
        return self._recvall()

    def proof_of_work(self):
        signal.alarm(60)
        random.seed(os.urandom(8))
        proof = ''.join(
            [random.choice(string.ascii_letters+string.digits) for _ in range(20)])
        _hexdigest = sha256(proof.encode()).hexdigest()
        self.send(f"[+] sha256(XXXX+{proof[4:]}) == {_hexdigest}".encode())
        x = self.recv(prompt=b'[+] Plz tell me XXXX: ')
        if len(x) != 4 or sha256(x+proof[4:].encode()).hexdigest() != _hexdigest:
            return False
        return True

    def handle(self):
        if not self.proof_of_work():
            self.send(b'[!] Wrong!')
            return
        signal.alarm(150)
        key = ?
        letters = list(ascii_uppercase)
        others = "".join([choice(letters) for i in range(30)])
        pos = randint(0, len(others))
        text = others[:pos]+key+others[pos:]
        dayrotors = tuple(random.sample(myrotors, 3))
        for times in range(10):
            tmpkey = "".join([choice(letters) for i in range(3)])
            shuffle(letters)
            plugin = " ".join([letters[2*i]+letters[2*i+1] for i in range(10)])
            myEnigma = enigma.Enigma(myReflector, *dayrotors, tmpkey, plugin)
            ctx = myEnigma.encipher(text)
            self.send(ctx.encode())
        datekey = "".join([choice(letters) for i in range(3)])
        shuffle(letters)
        plugin = " ".join([letters[2*i]+letters[2*i+1] for i in range(10)])
        myEnigma = enigma.Enigma(myReflector, *dayrotors, datekey, plugin)
        ctx = myEnigma.encipher(text)
        self.send(ctx.encode())
        self.send(b"now give me the plaintext:")
        ans = self.recv().decode()

        if not check(ans, text):
            self.send(b'nonono')
            return

        self.send(b'here is your flag')
        self.send(flag)


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 8840
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    print(HOST, PORT)
    server.serve_forever()
