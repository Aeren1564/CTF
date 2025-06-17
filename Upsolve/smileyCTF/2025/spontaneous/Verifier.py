from merkletree import MerkleTree
from ZKP import ZKP
from fft import ifft
class Verifier(ZKP):
    def verify(self, last_comm, roots, queries, max_degree):
        try:
            if len(roots) != self.r+1:
                return False

            αs = []
            for root in roots[:-1]:
                self.transcript.put(root)
                αs.append(self.transcript.get_challenge())
            
            self.transcript.put(last_comm)

            ω = self.ω

            for r in range(0, self.r):
                dl = self.domain_length >> r
                indexes = self.indices(dl, self.s)
                qs = queries[r]
                root = roots[r]
                α = αs[r]
                if len(qs) != len(indexes):
                    return False
                for i, idx in enumerate(indexes):
                    idx2 = (idx + dl // 2) % dl
                    if len(qs[i]) != 3:
                        return False
                    if any(len(x) != 2 for x in qs[i]):
                        return False
                    if not MerkleTree.verify_proof(root, qs[i][0][1], qs[i][0][0], idx):
                        return False
                    if not MerkleTree.verify_proof(root, qs[i][1][1], qs[i][1][0], idx2):
                        return False
                    if not MerkleTree.verify_proof(roots[r + 1], qs[i][2][1], qs[i][2][0], idx % (dl // 2)):
                        return False
                    ax = pow(ω,idx,self.p)
                    bx = pow(ω,idx2,self.p)
                    ay = qs[i][0][0]
                    by = qs[i][1][0]
                    cy = qs[i][2][0]
                    if ax == bx:
                        return False
                    s = (by - ay) * pow(bx - ax, -1, self.p) % self.p
                    b = (ay - s * ax) % self.p
                    if (s * α + b) % self.p != cy:
                        return False
                ω **= 2
                ω %= self.p
            
            if len(last_comm) != self.expansion_factor:
                return False
            
            if roots[-1] != MerkleTree(last_comm).get_root():
                return False        

            poly = ifft(last_comm, ω, self.p)
            deg_poly = poly.copy()
            while deg_poly and deg_poly[-1] == 0:
                deg_poly.pop(-1)
            deg = len(deg_poly) - 1
            assert self.domain_length//(2**self.r) == self.expansion_factor
            if deg > max_degree//(2**self.r):
                return False
            return True
        except:
            return False