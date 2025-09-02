import uuid
import functools
import secrets
import binascii
import time
import ec
import ecdsa
import struct
import tempfile
import subprocess
import hashlib

TIMEOUT = 1
SALT_LIMIT = 50

boottime = time.time()
signer = ecdsa.ECDSA(ec.secp256k1())

class Archive:
    SIGNATURE = 0xa075c93f
    HEADER = struct.Struct('<I16sd16sI')
    FOOTER = struct.Struct('<32s32s')
    salts = {}

    def __init__(self, user, zipdata):
        assert len(Archive.salts) < SALT_LIMIT
        self.user = user
        self.zip = zipdata
        self.crc = binascii.crc32(zipdata)
        self.id = uuid.uuid4()
        self.ts = time.time()
        self.salt = secrets.randbits(128).to_bytes(16)
        Archive.salts[self.id] = (self.user, self.salt)

    @functools.cached_property
    def data(self):
        return Archive.HEADER.pack(Archive.SIGNATURE, self.id.bytes, self.ts, self.user.id.bytes, self.crc) + self.zip

    @functools.cached_property
    def bytes(self):
        data = self.data
        sig = signer.sign(self.salt + data)
        return data + Archive.FOOTER.pack(sig[0].to_bytes(32), sig[1].to_bytes(32))

    def is_zipfile(zipdata):
        with tempfile.NamedTemporaryFile(suffix='.zip') as tmp:
            with open(tmp.name, 'wb') as f:
                f.write(zipdata)
            return subprocess.run(['zipinfo', tmp.name], capture_output=True, timeout=TIMEOUT).returncode == 0

    def is_archive(archive, user):
        if len(archive) <= Archive.HEADER.size + Archive.FOOTER.size:
            return False
        header, zipdata = archive[:Archive.HEADER.size], archive[Archive.HEADER.size:-Archive.FOOTER.size]
        signature, aid, ts, uid, crc = Archive.HEADER.unpack(header)
        if signature != Archive.SIGNATURE:
            return False
        if uuid.UUID(bytes=aid) not in Archive.salts:
            return False
        if not (boottime <= ts < time.time()):
            return False
        if uuid.UUID(bytes=uid) != user.id:
            return False
        if binascii.crc32(zipdata) != crc:
            return False
        if not Archive.is_zipfile(zipdata):
            return False
        return True

    def extract_id(archive, user):
        if not Archive.is_archive(archive, user):
            return None
        header = archive[:Archive.HEADER.size]
        signature, aid, ts, uid, crc = Archive.HEADER.unpack(header)
        return uuid.UUID(bytes=aid)
    
    def verify_signature(archive, salt):
        data, sig = archive[:-Archive.FOOTER.size], archive[-Archive.FOOTER.size:]
        sig = Archive.FOOTER.unpack(sig)
        sig = (int.from_bytes(sig[0]), int.from_bytes(sig[1]))
        return signer.verify(salt + data, sig)

    def is_valid(archive, user):
        aid = Archive.extract_id(archive, user)
        if aid is None:
            return False
        u, salt = Archive.salts[aid]
        if u != user:
            return False
        if not Archive.verify_signature(archive, salt):
            return False
        return True

    def extract_data(archive, user):
        if not Archive.is_valid(archive, user):
            return None
        return archive[Archive.HEADER.size:-Archive.FOOTER.size]

    def fetch_hash(archive, user):
        aid = Archive.extract_id(archive, user)
        if aid is None:
            return None
        u, salt = Archive.salts.get(aid)
        if u != user:
            return None
        data = archive[:-Archive.FOOTER.size]
        return str(signer.hash(salt + data)).encode()

    def proof_of_work(archive, proof):
        if len(archive) < Archive.FOOTER.size:
            return False
        sig = archive[-Archive.FOOTER.size:]
        return hashlib.sha512(sig + proof).hexdigest().startswith('0' * 32)

    def fetch_salt(archive, user, proof):
        # anti-bruteforce
        if not Archive.proof_of_work(archive, proof):
            return None
        aid = Archive.extract_id(archive, user)
        if aid is None:
            return None
        u, salt = Archive.salts.get(aid)
        if u != user:
            return None
        return salt
