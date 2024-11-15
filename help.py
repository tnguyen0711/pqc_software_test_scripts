import hashlib
import csv
import binascii

class ADRS:
    FORS_PRF = 0
    FORS_ROOTS = 1
    WOTS_PRF = 2
    WOTS_HASH = 3
    TREE = 4
    WOTS_PK = 5

    def __init__(self):
        self.key_pair_address = 0
        self.tree_height = 0
        self.tree_index = 0
        self.adrs_type = 0

    def copy(self):
        adrs_copy = ADRS()
        adrs_copy.key_pair_address = self.key_pair_address
        adrs_copy.tree_height = self.tree_height
        adrs_copy.tree_index = self.tree_index
        adrs_copy.adrs_type = self.adrs_type
        return adrs_copy

    def set_type_and_clear(self, adrs_type):
        self.adrs_type = adrs_type
        self.tree_height = 0
        self.tree_index = 0

    def set_key_pair_address(self, key_pair_address):
        self.key_pair_address = key_pair_address

    def set_tree_index(self, tree_index):
        self.tree_index = tree_index

    def set_tree_height(self, tree_height):
        self.tree_height = tree_height


class SHA256:
    def __init__(self, mode="sha256", verbose=0):
        if mode not in ["sha224", "sha256"]:
            print(f"Error: {mode} is not a supported mode.")
            return 0

        self.mode = mode
        self.verbose = verbose
        self.H = [0] * 8
        self.t1 = 0
        self.t2 = 0
        self.a = 0
        self.b = 0
        self.c = 0
        self.d = 0
        self.e = 0
        self.f = 0
        self.g = 0
        self.h = 0
        self.w = 0
        self.W = [0] * 16
        self.K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
            0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
            0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
            0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
            0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
            0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
            0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
            0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

    def init(self):
        if self.mode == "sha256":
            self.H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        else:
            self.H = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                      0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]

    def compute_hash(self, data):
        sha256 = hashlib.sha256()
        sha256.update(data)
        return sha256.digest()


class XMSS:
    def __init__(self, n=32, w=16, hp=5, d=1):
        self.n = n
        self.w = w
        self.hp = hp
        self.d = d

    def prf(self, pk_seed, sk_seed, adrs):
        sha256 = SHA256()
        adrs_bytes = str(adrs.__dict__).encode()
        return sha256.compute_hash(pk_seed + sk_seed + adrs_bytes)

    def h_h(self, pk_seed, adrs, nodes):
        sha256 = SHA256()
        adrs_bytes = str(adrs.__dict__).encode()
        return sha256.compute_hash(pk_seed + adrs_bytes + nodes)

    def wots_pkgen(self, sk_seed, pk_seed, adrs):
        sk_adrs = adrs.copy()
        sk_adrs.set_type_and_clear(ADRS.WOTS_PRF)
        sk_adrs.set_key_pair_address(adrs.key_pair_address)
        tmp = b''
        for i in range(self.n):
            sk_adrs.set_tree_index(i)
            sk = self.prf(pk_seed, sk_seed, sk_adrs)
            adrs.set_tree_index(i)
            tmp += self.h_h(pk_seed, adrs, sk)
        wotspk_adrs = adrs.copy()
        wotspk_adrs.set_type_and_clear(ADRS.WOTS_PK)
        pk = self.h_h(pk_seed, wotspk_adrs, tmp)
        return pk

    def xmss_node(self, sk_seed, i, z, pk_seed, adrs):
        if z == 0:
            adrs.set_type_and_clear(ADRS.WOTS_HASH)
            adrs.set_key_pair_address(i)
            node = self.wots_pkgen(sk_seed, pk_seed, adrs)
        else:
            lnode = self.xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
            rnode = self.xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
            adrs.set_type_and_clear(ADRS.TREE)
            adrs.set_tree_height(z)
            adrs.set_tree_index(i)
            node = self.h_h(pk_seed, adrs, lnode + rnode)
        return node

    def slh_keygen_internal(self, sk_seed, sk_prf, pk_seed):
        adrs = ADRS()
        pk_root = self.xmss_node(sk_seed, 0, self.hp, pk_seed, adrs)
        sk = sk_seed + sk_prf + pk_seed + pk_root
        pk = pk_seed + pk_root
        signature = self.sign_message(sk, b'Example message')
        return pk, sk, signature

    def sign_message(self, private_key, message):
        sha256 = SHA256()
        return sha256.compute_hash(private_key + message)


class FORS:
    def __init__(self, n=32, a=5, k=2):
        self.n = n
        self.a = a
        self.k = k

    def prf(self, pk_seed, sk_seed, adrs):
        sha256 = SHA256()
        adrs_bytes = str(adrs.__dict__).encode()
        return sha256.compute_hash(pk_seed + sk_seed + adrs_bytes)

    def h_f(self, pk_seed, adrs, sk):
        sha256 = SHA256()
        adrs_bytes = str(adrs.__dict__).encode()
        return sha256.compute_hash(pk_seed + adrs_bytes + sk)

    def fors_gen_leaf(self, sk_seed, pk_seed, adrs):
        adrs.set_type_and_clear(ADRS.FORS_PRF)
        sk = self.prf(pk_seed, sk_seed, adrs)
        adrs.set_type_and_clear(ADRS.FORS_ROOTS)
        leaf = self.h_f(pk_seed, adrs, sk)
        return leaf

    def fors_treehash(self, sk_seed, pk_seed, s, t, adrs):
        if t == 0:
            adrs.set_tree_index(s)
            return self.fors_gen_leaf(sk_seed, pk_seed, adrs)
        else:
            lnode = self.fors_treehash(sk_seed, pk_seed, s, t - 1, adrs)
            rnode = self.fors_treehash(sk_seed, pk_seed, s + (1 << (t - 1)), t - 1, adrs)
            adrs.set_type_and_clear(ADRS.FORS_ROOTS)
            adrs.set_tree_height(t)
            adrs.set_tree_index(s // (1 << t))
            node = self.h_f(pk_seed, adrs, lnode + rnode)
        return node

    def fors_pkgen(self, sk_seed, pk_seed, adrs):
        fors_pk = b''
        for i in range(self.k):
            adrs.set_key_pair_address(i)
            root = self.fors_treehash(sk_seed, pk_seed, 0, self.a, adrs)
            fors_pk += root
        return fors_pk

    def fors_keygen_internal(self, sk_seed, sk_prf, pk_seed):
        adrs = ADRS()
        fors_pk = self.fors_pkgen(sk_seed, pk_seed, adrs)
        sk = sk_seed + sk_prf + pk_seed + fors_pk
        pk = pk_seed + fors_pk
        signature = self.sign_message(sk, b'Example message')
        return pk, sk, signature

    def sign_message(self, private_key, message):
        sha256 = SHA256()
        return sha256.compute_hash(private_key + message)


def save_to_csv(filename, xmss_pk, xmss_sk, xmss_signature, fors_pk, fors_sk, fors_signature):
    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Algorithm", "Public Key", "Private Key", "Signature"])
        writer.writerow([
            "XMSS",
            binascii.hexlify(xmss_pk).decode(),
            binascii.hexlify(xmss_sk).decode(),
            binascii.hexlify(xmss_signature).decode()
        ])
        writer.writerow([
            "FORS",
            binascii.hexlify(fors_pk).decode(),
            binascii.hexlify(fors_sk).decode(),
            binascii.hexlify(fors_signature).decode()
        ])
    print(f"Keys and signatures saved to {filename}")


# Example usage
xmss = XMSS()
xmss_pk, xmss_sk, xmss_signature = xmss.slh_keygen_internal(b'sk_seed_xmss', b'sk_prf_xmss', b'pk_seed_xmss')

fors = FORS()
fors_pk, fors_sk, fors_signature = fors.fors_keygen_internal(b'sk_seed_fors', b'sk_prf_fors', b'pk_seed_fors')

save_to_csv("keys_and_signatures.csv", xmss_pk, xmss_sk, xmss_signature, fors_pk, fors_sk, fors_signature)
