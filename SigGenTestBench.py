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


class XMSS:
    def __init__(self, n=32, w=16, hp=5, d=1):
        self.n = n  # Security parameter (hash output size in bytes)
        self.w = w  # Winternitz parameter
        self.hp = hp  # Height of the XMSS tree
        self.d = d  # Layers

    def prf(self, pk_seed, sk_seed, adrs):
        return hashlib.sha256(pk_seed + sk_seed + str(adrs).encode()).digest()

    def h_h(self, pk_seed, adrs, nodes):
        return hashlib.sha256(pk_seed + str(adrs).encode() + nodes).digest()

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
        return pk, sk


class FORS:
    def __init__(self, n=32, a=5, k=2):
        self.n = n  # Security parameter (hash output size in bytes)
        self.a = a  # Height of the FORS tree
        self.k = k  # Number of FORS trees

    def prf(self, pk_seed, sk_seed, adrs):
        return hashlib.sha256(pk_seed + sk_seed + str(adrs).encode()).digest()

    def h_f(self, pk_seed, adrs, sk):
        return hashlib.sha256(pk_seed + str(adrs).encode() + sk).digest()

    def h_h(self, pk_seed, adrs, nodes):
        return hashlib.sha256(pk_seed + str(adrs).encode() + nodes).digest()

    def h_t(self, pk_seed, adrs, root):
        return hashlib.sha256(pk_seed + str(adrs).encode() + root).digest()

    def base_2b(self, md, a, k):
        indices = [int.from_bytes(md[i:i + 1], 'big') % (2 ** a) for i in range(k)]
        return indices

    def fors_sk_gen(self, sk_seed, pk_seed, adrs, idx):
        sk_adrs = adrs.copy()
        sk_adrs.set_type_and_clear(ADRS.FORS_PRF)
        sk_adrs.set_key_pair_address(adrs.key_pair_address)
        sk_adrs.set_tree_index(idx)
        return self.prf(pk_seed, sk_seed, sk_adrs)

    def fors_node(self, sk_seed, i, z, pk_seed, adrs):
        if z == 0:
            sk = self.fors_sk_gen(sk_seed, pk_seed, adrs, i)
            adrs.set_tree_height(0)
            adrs.set_tree_index(i)
            node = self.h_f(pk_seed, adrs, sk)
        else:
            lnode = self.fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
            rnode = self.fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
            adrs.set_tree_height(z)
            adrs.set_tree_index(i)
            node = self.h_h(pk_seed, adrs, lnode + rnode)
        return node

    def fors_sign(self, message, sk_seed, pk_seed, adrs):
        sig_fors = b''
        md = hashlib.sha256(message.encode()).digest()
        indices = self.base_2b(md, self.a, self.k)
        for i in range(self.k):
            sig_fors += self.fors_sk_gen(sk_seed, pk_seed, adrs, (i << self.a) + indices[i])
            for j in range(self.a):
                s = (indices[i] >> j) ^ 1
                sig_fors += self.fors_node(sk_seed, (i << (self.a - j)) + s, j, pk_seed, adrs)
        return sig_fors


# Fixed seeds for testing
sk_seed = b'sk_seed_for_testing_purposes'
pk_seed = b'pk_seed_for_testing_purposes'
sk_prf = b'sk_prf_for_testing_purposes'

# Message to sign
message = "Test message for FORS signature generation."

# Initialize XMSS and FORS
xmss = XMSS()
fors = FORS()
adrs = ADRS()

# Generate XMSS keys
pk, sk = xmss.slh_keygen_internal(sk_seed, sk_prf, pk_seed)

# Generate FORS signature
signature = fors.fors_sign(message, sk_seed, pk_seed, adrs)

# Write public key, private key, and signature to CSV
with open("output_keys_and_signature.csv", mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Public Key", "Private Key", "Signature"])
    writer.writerow([pk.hex(), sk.hex(), signature.hex()])

print("Public Key, Private Key, and Signature in output_keys_and_signature.csv")