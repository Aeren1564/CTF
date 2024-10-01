import hashlib
import struct


chunk_size = 16
leaf_node_identifier = b"L"
empty_node_identifier = b"E"
internal_node_identifier = b"I"


def get_chunks(xs, n: int = chunk_size):
    for i in range(0, len(xs), n):
        yield xs[i : i + n]


def pairwise(xs):
    # # pairwise('ABCDEF') → AB BC CD DE EF F
    iterator = iter(xs)
    while True:
        a = next(iterator, None)
        b = next(iterator, None)
        if a != None:
            yield a, b
        else:
            break


def get_hash(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


class TreeStore:
    def __init__(self):
        self.table = dict()

    def add_file(self, file: bytes):
        added_chunks = 0

        hashes = []
        for chunk in get_chunks(file):
            data = leaf_node_identifier + chunk
            hash = get_hash(data)
            if hash not in self.table:
                self.table[hash] = data
                added_chunks += 1
            hashes.append(hash)

        while len(hashes) > 1:
            new_hashes = []
            for left, right in pairwise(hashes):
                if right == None:
                    right = empty_node_identifier

                data = internal_node_identifier + left + right
                hash = get_hash(data)
                if hash not in self.table:
                    self.table[hash] = data
                    added_chunks += 1
                new_hashes.append(hash)

            hashes = new_hashes

        print(f"{added_chunks} chunks were added")

    def get_file(self, hash: bytes):
        raise NotImplementedError
