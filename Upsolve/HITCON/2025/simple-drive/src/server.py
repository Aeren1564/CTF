import http.server
import http.cookies
import urllib
import functools
import user
import archive
import signal

COOKIE_KEY = 'hitconctf'

class HTTPHandler(http.server.BaseHTTPRequestHandler):
    @functools.cached_property
    def urlparse(self):
        return urllib.parse.urlparse(self.path)

    @functools.cached_property
    def reqpath(self):
        return self.urlparse.path

    @functools.cached_property
    def query(self):
        return dict(urllib.parse.parse_qsl(self.urlparse.query))

    @functools.cached_property
    def bodysz(self):
        return int(self.headers.get("Content-Length", 0))

    @functools.cached_property
    def body(self):
        return self.rfile.read(self.bodysz)

    @functools.cached_property
    def form(self):
        return dict(urllib.parse.parse_qsl(self.body))

    @functools.cached_property
    def cookies(self):
        return http.cookies.SimpleCookie(self.headers.get("Cookie"))

    def handle_request(self, router, auth_router):
        self.protocol_version = 'HTTP/1.1'
        if self.reqpath in router:
            status, headers, body = router[self.reqpath]()
        elif self.reqpath in auth_router:
            cookie = self.cookies.get(COOKIE_KEY)
            if cookie is not None and (u := user.auth(cookie.value)) is not None:
                status, headers, body = auth_router[self.reqpath](u)
            else:
                status, headers, body = 401, {}, b''
        else:
            status, headers, body = 404, {}, b''
        if self.headers.get('Connection', '') == 'keep-alive':
            headers['Connection'] = 'keep-alive'
        else:
            headers['Connection'] = 'close'
        headers['Content-Length'] = str(len(body))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        router = {'/pubkey': self.get_pubkey}
        auth_router = {'/read': self.get_read, '/listdir': self.get_listdir, '/download': self.get_download, '/backup': self.get_backup, '/hash': self.get_hash, '/salt': self.get_salt}
        self.handle_request(router, auth_router)

    def do_POST(self):
        router = {'/register': self.post_register, '/login': self.post_login}
        auth_router = {'/logout': self.post_logout, '/upload': self.post_upload, '/mkdir': self.post_mkdir, '/rm': self.post_rm, '/restore': self.post_restore, '/verify': self.post_verify}
        self.handle_request(router, auth_router)

    def post_register(self):
        if b'username' not in self.form or b'password' not in self.form:
            return 400, {}, b''
        username = self.form.get(b'username').decode()
        password = self.form.get(b'password').decode()
        if user.register(username, password):
            return 200, {}, b''
        else:
            return 403, {}, b''

    def post_login(self):
        if b'username' not in self.form or b'password' not in self.form:
            return 400, {}, b''
        username = self.form.get(b'username').decode()
        password = self.form.get(b'password').decode()
        cookie = user.login(username, password)
        if cookie is None:
            return 403, {}, b''
        return 200, {'Set-Cookie': f'{COOKIE_KEY}={cookie};'}, b''

    def post_logout(self, u):
        user.logout(self.cookies.get(COOKIE_KEY).value)
        return 200, {}, b''

    def post_upload(self, u):
        if 'path' not in self.query:
            return 400, {}, b''
        if u.fs.upload(self.query.get('path'), self.body):
            return 200, {}, b''
        else:
            return 400, {}, b''

    def post_mkdir(self, u):
        if 'path' not in self.query:
            return 400, {}, b''
        if u.fs.mkdir(self.query.get('path')):
            return 200, {}, b''
        else:
            return 400, {}, b''

    def post_rm(self, u):
        if 'path' not in self.query:
            return 400, {}, b''
        if u.fs.rm(self.query.get('path')):
            return 200, {}, b''
        else:
            return 400, {}, b''

    def get_read(self, u):
        if 'path' not in self.query:
            return 400, {}, b''
        data = u.fs.read(self.query.get('path'))
        if data is not None:
            return 200, {'Content-Type': 'application/octet-stream'}, data
        else:
            return 400, {}, b''

    def get_listdir(self, u):
        if 'path' not in self.query:
            return 400, {}, b''
        dirs = u.fs.listdir(self.query.get('path'))
        if dirs is not None:
            return 200, {'Content-Type': 'text/plain'}, '\n'.join(dirs).encode()
        else:
            return 400, {}, b''

    def get_download(self, u):
        if 'path' not in self.query:
            return 400, {}, b''
        data = u.fs.download(self.query.get('path'))
        if data is not None:
            return 200, {'Content-Type': 'application/octet-stream'}, data
        else:
            return 400, {}, b''

    def get_backup(self, u):
        data = u.fs.backup()
        if data is not None:
            return 200, {'Content-Type': 'application/octet-stream'}, data
        else:
            return 400, {}, b''

    def post_verify(self, u):
        if u.fs.verify(self.body):
            return 200, {}, b''
        else:
            return 400, {}, b''

    def post_restore(self, u):
        if u.fs.restore(self.body):
            return 200, {}, b''
        else:
            return 400, {}, b''

    def get_pubkey(self):
        return 200, {}, archive.signer.compressed_pubkey.encode()

    def get_hash(self, u):
        hash_value = archive.Archive.fetch_hash(self.body, u)
        if hash_value is not None:
            return 200, {'Content-Type': 'application/octet-stream'}, hash_value
        else:
            return 400, {}, b''

    def get_salt(self, u):
        if 'pow' not in self.query:
            return 400, {}, b''
        salt = archive.Archive.fetch_salt(self.body, u, self.query.get('pow').encode())
        if salt is not None:
            return 200, {'Content-Type': 'application/octet-stream'}, salt
        else:
            return 400, {}, b''

if __name__ == '__main__':
    signal.alarm(180)
    httpd = http.server.HTTPServer(('', 5487), HTTPHandler)
    httpd.serve_forever()
