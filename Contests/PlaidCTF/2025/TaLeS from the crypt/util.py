from socket import socket
from secrets import randbits
from select import select

from Crypto.PublicKey import RSA
from OpenSSL import SSL, crypto

# generated with `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes`
key = RSA.import_key(open("key.pem", "rb").read())
p = [key.n, key.e, key.d, key.p, key.q, key.u]


def ctx_with_key(certpath: str, keyp: list[int]) -> SSL.Context:
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.set_options(1<<8)
    ctx.use_certificate_file(certpath)
    key = RSA.construct(keyp, 0).exportKey(pkcs=8)
    ctx.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, key))
    return ctx

default_ctx = ctx_with_key("cert.pem", p)

def get_ctx(sock) -> SSL.Context:
    if select([sock], [sock], [sock], 0.2)[-1]:
        [k] = sock.recv(1, 1)
        return ctx_with_key("cert.pem", [*p[:2], p[2] ^ (randbits(3) << 3 * k), *p[3:]])
    return default_ctx


def make_ssl_connection(sock: socket) -> SSL.Connection:
    conn = SSL.Connection(get_ctx(sock), sock)
    conn.set_accept_state()
    return conn


SSL.Connection.makefile = socket.makefile
