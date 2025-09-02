import random
import base64
import time
import hashlib
import uuid
import fs

MAX_USERS = 10
MAX_COOKIES = 50

class User:
    def __init__(self, username, password):
        self.id = uuid.uuid4()
        self.username = username
        self.salt = random.randbytes(8)
        self.password = self.hash(password)
        self.fs = fs.FileSystem(self)

    def hash(self, password):
        return hashlib.sha3_512(self.salt + password.encode()).hexdigest()
    
    def check_password(self, password):
        return self.hash(password) == self.password

class Cookie:
    def __init__(self, user):
        self.user = user
        self.exp = time.time() + 60
        self.id = Cookie.gen()
    
    def gen():
        return base64.b64encode(random.randbytes(32)).decode().rstrip('=')

users = {}
cookies = {}

def register(username, password):
    if username in users or len(users) >= MAX_USERS:
        return False
    users[username] = User(username, password)
    return True

def login(username, password):
    if username not in users:
        return None
    user = users[username]
    if not user.check_password(password):
        return None
    if len(cookies) >= MAX_COOKIES:
        return None
    cookie = Cookie(user)
    cookies[cookie.id] = cookie
    return cookie.id

def auth(cookie):
    if cookie not in cookies:
        return None
    cookie = cookies[cookie]
    if time.time() >= cookie.exp:
        cookies.pop(cookie.id)
        return None
    return cookie.user

def logout(cookie):
    if cookie in cookies:
        cookies.pop(cookie)
