from sage.all import *
import socketserver
from flag import flag
p = 2**302 + 307
k = 140
n = 10
alpha = 3

def Matrix2strlist(M):
    alist = []
    for i in range(n):
        templist = []
        for j in range(n):
            templist.append(hex(M[i,j])[2:])
        alist.append(' '.join(templist).encode())
    return alist

def strlist2Matrix(s):
    M = Matrix(GF(p) , n)
    for i in range(n):
        linelist = s[i].split(b" ")
        for j in range(n):
            M[i,j] = int(linelist[j],16)
    return M
def check_M(M):
    for i in range(n):
        for j in range(n):
            if M[i,j] < 0 or M[i,j] >= alpha:
                return 0
    return 1
class server(socketserver.BaseRequestHandler):

    def _recv(self):
        BUFF_SIZE = 1024
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def _send(self, msg, newline=True):

        if isinstance(msg , str):
            msg = msg.encode()
        if newline:
            msg += b"\n"
        self.request.sendall(msg)

    def handle(self):
        Dlist = load("./Matrix3/Dlist.sobj")
        self._send(b"please give me E(line by line)")
        Elist = []
        for i in range(10):
            self._send(b"> " , newline=False)
            Elist.append(self._recv())

        E = strlist2Matrix(Elist)
        print(E)
        E_1 = E**-1
        for i in range(k):
            if check_M(E_1*Dlist[i]*E) == 0:
                self._send(b"your private key is wrong")
                return 0
        self._send(b"your flag is")
        self._send(flag)
        return 0

    def finish(self):
        self.request.close()

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10001
    server = ForkedServer((HOST, PORT), server)
    server.allow_reuse_address = True
    server.serve_forever()
 
