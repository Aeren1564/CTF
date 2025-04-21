from Crypto.Cipher import AES
from hashlib import sha3_512
import secrets
import json
from dataclasses import dataclass
from typing import List

# N = random_prime(2^512)
N = 7314115252283636608283909725370457727076563580799920315154071960840699660519829311181093122148272777913745382460410854655175915612132848738615987055676619

# returns random number in field mod N
def random_n():
    return secrets.randbelow(N)

def random_poly(degree):
    return [random_n() for _ in range(degree + 1)]

# polynomial coefficents is list of coeffiecients with index 0 being constant,
# index 1 being in front of x, index 2 x^2, etc
def eval_poly(coefficients, x):
    return sum(c * x**i for i, c in enumerate(coefficients)) % N

def poly_mult(p1, p2):
    out = [0] * (len(p1) + len(p2) - 1)

    for i1, c1 in enumerate(p1):
        for i2, c2 in enumerate(p2):
            out[i1 + i2] = (out[i1 + i2] + (c1 * c2)) % N

    return out

def poly_add(p1, p2):
    diff = len(p1) - len(p2)
    if diff < 0:
        p1 = p1 + ([0] * -diff)
    else:
        p2 = p2 + ([0] * diff)
        
    return [(c1 + c2) % N for c1, c2 in zip(p1, p2)]

def make_lagrange_part(other_points, current_point):
    # poly = (x - x1)(x - x2)...(x - xn)
    poly = [1]
    for x, y in other_points:
        poly = poly_mult(poly, [-x, 1])

    x, y = current_point
    c = pow(eval_poly(poly, x), -1, N) * y
    return poly_mult([c], poly)

def lagrange_interpolate(points):
    poly = [0]

    for i in range(len(points)):
        current_point = points[i]
        other_points = points[:i] + points[i+1:]
        poly = poly_add(poly, make_lagrange_part(other_points, current_point))

    return poly

def id_to_bytes(n):
    return sha3_512(n.to_bytes(512, 'little')).digest()

# hash bytes to element of field Z_N
def hash(data):
    return int.from_bytes(sha3_512(data).digest(), 'little') % N

SHARE_PAD_ID = b'share_'
SECRET_PAD_ID = b'secret'

# Encrypts message using element of field Z_N as key
def encrypt(key_n: int, message: bytes):
    key = id_to_bytes(key_n)[:32]
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, mode = AES.MODE_CTR, nonce = nonce)

    return nonce + cipher.encrypt(message)

# Encrypts message using element of field Z_N as key
def decrypt(key_n: int, ct: bytes):
    key = id_to_bytes(key_n)[:32]
    nonce = ct[:12]
    cipher = AES.new(key, mode = AES.MODE_CTR, nonce = nonce)

    return cipher.decrypt(ct[12:])

# used to generate provisioning data
@dataclass
class ProvisionKey:
    share_salt: List[bytes]
    secret_salt: List[bytes]

    @classmethod
    def generate(cls, n):
        return cls(
            share_salt = [secrets.token_bytes(64) for _ in range(n)],
            secret_salt = [secrets.token_bytes(64) for _ in range(n)],
        )

    # number of shared needed to obtain secret
    def share_count(self):
        return len(self.share_salt)

    def share_pad(self, share_id, index):
        return hash(SHARE_PAD_ID + self.share_salt[index] + id_to_bytes(share_id))

    def secret_pad(self, share_id, index):
        return hash(SECRET_PAD_ID + self.secret_salt[index] + id_to_bytes(share_id))

# used to generate shares
@dataclass
class PssKey:
    base_polys: List[List[int]]
    provision_key: ProvisionKey

    @classmethod
    def generate(cls, n):
        assert n > 2
        return cls(
            base_polys = [random_poly(n - 1) for _ in range(n)],
            provision_key = ProvisionKey.generate(n),
        )

    def share_count(self):
        return len(self.base_polys)

@dataclass
class Share:
    share_id: int
    padded_shares: List[int]
    secret_ct: List[bytes]

    def to_json(self):
        return json.dumps({
            'share_id': self.share_id,
            'padded_shares': self.padded_shares,
            'secret_ct': [ct.hex() for ct in self.secret_ct],
        })

    @classmethod
    def from_json(cls, data):
        data = json.loads(data)
        return cls(data['share_id'], data['padded_shares'], [bytes.fromhex(ct) for ct in data['secret_ct']])

@dataclass
class ProvisionData:
    pads: List[int]

    def to_json(self):
        return json.dumps({
            'pads': self.pads,
        })

    @classmethod
    def from_json(cls, data):
        data = json.loads(data)
        return cls(data['pads'])

    def share_count(self):
        return len(self.pads)

def verify_id(n):
    assert type(n) == int
    # 0 is reserved for polynomial secret
    assert n >= 1 and n < N

# generates a share with the given id and secret
def generate_share(key: PssKey, share_id: int, secret: bytes) -> Share:
    verify_id(share_id)

    padded_shares = []
    secret_ct = []
    for i in range(key.share_count()):
        share = eval_poly(key.base_polys[i], share_id)
        share_pad = key.provision_key.share_pad(share_id, i)
        padded_share = (share - share_pad) % N

        secret_pad = key.provision_key.secret_pad(share_id, i)
        base_secret = eval_poly(key.base_polys[i], 0)
        ct = encrypt((base_secret + secret_pad) % N, secret)

        padded_shares.append(padded_share)
        secret_ct.append(ct)

    return Share(share_id, padded_shares, secret_ct)

# Creates provisioning data which only allows recovering the secrets with shares specified in share_id list
def provision(key: ProvisionKey, share_ids: List[int]) -> ProvisionData:
    # number of ids has to match amount secret sharing system was provisioned for
    assert len(share_ids) == key.share_count()

    for id in share_ids:
        verify_id(id)

    # check no duplicates
    assert len(share_ids) == len(set(share_ids))

    pads = []
    for i, id in enumerate(share_ids):
        share_pads = [
            (pad_id, key.share_pad(pad_id, i)) for pad_id in share_ids
        ]

        poly = lagrange_interpolate(share_pads)

        secret_pad = key.secret_pad(id, i)
        pads.append((eval_poly(poly, 0) + secret_pad) % N)

    return ProvisionData(pads)

# recovers the secret for each of the shares as long as the provisioning data matches
# NOTE: challenge server does not run this function, it is for demonstration purposes
def recover_secrets(provision_data: ProvisionData, shares: List[Share]) -> List[bytes]:
    assert len(shares) == provision_data.share_count()

    secrets = []
    for i, current_share in enumerate(shares):
        share_points = [
            (share.share_id, share.padded_shares[i]) for share in shares
        ]

        poly = lagrange_interpolate(share_points)
        key = (
            eval_poly(poly, 0) + provision_data.pads[i]
        ) % N

        secrets.append(decrypt(key, current_share.secret_ct[i]))

    return secrets
