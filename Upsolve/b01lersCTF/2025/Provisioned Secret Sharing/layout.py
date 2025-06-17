from CTF_Library import *

"""
N: 512 bit prime
F = GF(N)
n = share_count = 5
SHARE_PAD_ID = b'share_'
SECRET_PAD_ID = b'secret'

[ProvisionKey]
share_salt: List[64 bytes], fixed random
secret_salt: List[64 bytes], fixed random
share_pad(share_id, index): returns hash(SHARE_PAD_ID + share_salt[index] + id_to_bytes(share_id)) in F
secret_pad(share_id, index): returns hash(SECRET_PAD_ID + secret_salt[index] + id_to_bytes(share_id)) in F

[Psskey]: generated once each run
base_polys: List[List[int]], deg n-1, fixed random, in List[F[X]]
provision_key: ProvisionKey, fixed random

[Share]
share_id: int
padded_shares: List[int] in List[F]
secret_ct: List[bytes]
to_json(self) and from_json(cls, data)

[ProvisionData]
pads: List[int]
to_json() and from_json()

--------------------------------------------------------------------
[generate_share(key: PssKey, share_id: int, secret: bytes)]
i=0~n-1

padded_share[i] = base_polys[i](share_id) - share_pad(share_id, i)
ct[i] = encrypt(base_polys[i](0) + secret_pad(share_id, i), secret)

Returns padded_share and ct
--------------------------------------------------------------------
[provision(key: ProvisionKey, share_ids: List[int])] no duplicate share_ids allowed
i=0~n-1

share_pads[i] = [(pad_id, share_pad(pad_id, i)) for pad_id in share_ids]
poly = lagrange(share_pads[i])
pads[i] = lagrange(share_pads[i])(0) + secret_pad(share_ids[i], i)

return pads
--------------------------------------------------------------------
"""