from hashlib import sha256

class MerkleTree:
    def __init__(self, leaves):
        self.leaves = leaves
        self.tree = []
        self.build_tree()

    @classmethod
    def handle(cls, leaf):
        if isinstance(leaf, str):
            return leaf.encode()
        elif isinstance(leaf, bytes):
            return leaf
        elif isinstance(leaf, int):
            return cls.handle(str(leaf))
         
    def build_tree(self):
        current_level = [sha256(self.handle(leaf)).hexdigest() for leaf in self.leaves]
        self.tree.append(current_level)

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined_hash = sha256((current_level[i] + current_level[i + 1]).encode()).hexdigest()
                else:
                    combined_hash = current_level[i]
                next_level.append(combined_hash)
            current_level = next_level
            self.tree.append(current_level)

    def get_root(self):
        return self.tree[-1][0] if self.tree else None
    
    def get_proof(self, index):
        if index < 0 or index >= len(self.leaves):
            raise IndexError("Index out of bounds")
        proof = []
        current_index = index
        for level in self.tree[:-1]:
            if current_index % 2 == 0:
                sibling_index = current_index + 1
            else:
                sibling_index = current_index - 1
            
            if sibling_index < len(level):
                proof.append(level[sibling_index])
            else:
                raise IndexError("Sibling index out of bounds")
            current_index //= 2
        return proof
    
    @classmethod
    def verify_proof(cls, root, proof, leaf, index):
        current_hash = sha256(cls.handle(leaf)).hexdigest()
        
        for sibling in proof:
            if index % 2 == 0:
                current_hash = sha256((current_hash + sibling).encode()).hexdigest()
            else:
                current_hash = sha256((sibling + current_hash).encode()).hexdigest()
            index //= 2

        return current_hash == root

    def __repr__(self):
        return f"MerkleTree(root={self.get_root()})"
