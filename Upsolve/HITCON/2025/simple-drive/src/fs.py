import tempfile
import subprocess
import os
import archive
import time
import string

SIZE_LIMIT = 1 << 20
DIR_LIMIT = 16
TIMEOUT = 1
ALLOW_CHARSET = set(string.ascii_letters + string.digits + './-_')

class FileSystem:
    def __init__(self, user):
        self.user = user
        self.rootdir = tempfile.TemporaryDirectory()
        self.size = 0
        self.dirs = 0

    def check_path(self, path):
        return set(path).issubset(ALLOW_CHARSET)

    def path(self, path):
        return os.path.join(self.rootdir.name, os.path.normpath(os.path.join('/', path))[1:])

    def zip(self, path = None):
        if path is None:
            path = self.rootdir.name
        if os.path.isdir(path):
            p = subprocess.run(['zip', '-r', '-', '.'], capture_output=True, cwd=path, timeout=TIMEOUT)
        else:
            p = subprocess.run(['zip', '-r', '-', os.path.basename(path)], capture_output=True, cwd=os.path.dirname(path), timeout=TIMEOUT)
        if p.returncode != 0:
            return None
        if len(p.stdout) > SIZE_LIMIT:
            return None
        return p.stdout

    def unzip(self, zipdata):
        with tempfile.NamedTemporaryFile(suffix='.zip') as tmp:
            with open(tmp.name, 'wb') as f:
                f.write(zipdata)
            p = subprocess.run(['unzip', '-o', tmp.name], capture_output=True, cwd=self.rootdir.name, timeout=TIMEOUT)
        if p.returncode != 0:
            return False
        return True

    def upload(self, path, content):
        if not self.check_path(path):
            return False
        path = self.path(path)
        if not os.path.isdir(os.path.dirname(path)):
            return False
        if os.path.isdir(path):
            return False
        if self.size + len(content) > SIZE_LIMIT:
            return False
        with open(path, 'wb') as f:
            f.write(content)
        self.size += len(content)
        return True

    def read(self, path):
        path = self.path(path)
        if not os.path.isfile(path):
            return None
        with open(path, 'rb') as f:
            return f.read()

    def mkdir(self, path):
        if not self.check_path(path):
            return False
        path = self.path(path)
        if not os.path.isdir(os.path.dirname(path)):
            return False
        if os.path.exists(path):
            return False
        if self.dirs + 1 > DIR_LIMIT:
            return False
        os.mkdir(path)
        self.dirs += 1
        return True

    def listdir(self, path):
        path = self.path(path)
        if not os.path.isdir(path):
            return None
        return os.listdir(path)

    def rm(self, path):
        path = self.path(path)
        if not os.path.exists(path):
            return False
        if os.path.isdir(path):
            if len(os.listdir(path)) > 0:
                return False
            os.rmdir(path)
        else:
            os.remove(path)
        return True

    def download(self, path):
        path = self.path(path)
        if not os.path.exists(path):
            return None
        return self.zip(path)

    def backup(self):
        zipdata = self.zip()
        if zipdata is None:
            return None
        return archive.Archive(self.user, zipdata).bytes

    def restore(self, backup):
        zipdata = archive.Archive.extract_data(backup, self.user)
        if zipdata is None:
            return False
        return self.unzip(zipdata)

    def verify(self, backup):
        return archive.Archive.is_valid(backup, self.user)
