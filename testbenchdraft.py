import hashlib
import csv


class ADRS:

    WOTS_PRF = 0
    WOTS_HASH = 1
    TREE = 2
    WOTS_PK = 3

    def __init__(self):
        self.a = bytearray(32)

    def set_layer_address(self, x):
        """Set layer address."""
        self.a[0:4] = x.to_bytes(4, byteorder='big')

    def set_key_pair_address(self, x):
        """Set key pair Address."""
        self.a[20:24] = x.to_bytes(4, byteorder='big')

    def get_key_pair_address(self):
        """Get the key pair address as an integer."""
        return int.from_bytes(self.a[20:24], byteorder='big')

    def set_tree_index(self, x):
        """Set FORS tree index."""
        self.a[28:32] = x.to_bytes(4, byteorder='big')

    def set_tree_height(self, x):
        """Set tree height."""
        self.a[24:28] = x.to_bytes(4, byteorder='big')

    def set_type_and_clear(self, t):
        """Set type and clear certain bytes."""
        self.a[16:20] = t.to_bytes(4, byteorder='big')
        for i in range(12):
            self.a[20 + i] = 0

    def copy(self):
        new_adrs = ADRS()
        new_adrs.a = self.a[:]
        return new_adrs


class XMSS:
    def __init__(self, n=32, w=16, hp=5, d=1):
        self.n = n  # Security parameter (hash output size in bytes)
        self.w = w  # Winternitz parameter
        self.hp = hp  # Height of the XMSS tree
        self.d = d  # Layers

    def prf(self, pk_seed, sk_seed, adrs):
        """PRF function based on SHA-256."""
        return hashlib.sha256(pk_seed + sk_seed + adrs.a).digest()

    def h_h(self, pk_seed, adrs, nodes):
        """Hash function for internal nodes."""
        return hashlib.sha256(pk_seed + adrs.a + nodes).digest()

    def wots_pkgen(self, sk_seed, pk_seed, adrs):
        """Generate a WOTS+ public key."""
        sk_adrs = adrs.copy()
        sk_adrs.set_type_and_clear(ADRS.WOTS_PRF)
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
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
        """Compute the root of a Merkle subtree."""
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
        """Algorithm 18: slh_keygen_internal()."""
        adrs = ADRS()
        adrs.set_layer_address(self.d - 1)
        pk_root = self.xmss_node(sk_seed, 0, self.hp, pk_seed, adrs)
        sk = sk_seed + sk_prf + pk_seed + pk_root
        pk = pk_seed + pk_root
        return pk, sk


# Create XMSS instance and constants
xmss = XMSS()
sk_seed = b'sk0123456789' * 2  # Constant seed for secret key (32 bytes)
pk_seed = b'pk0123456789' * 2  # Constant seed for public key (32 bytes)
sk_prf = b'prf0123456789' * 2  # Constant PRF value (32 bytes)

# Generate keys
pk, sk = xmss.slh_keygen_internal(sk_seed, sk_prf, pk_seed)

# Write keys to CSV
with open("xmss_keys.csv", mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Public Key", "Private Key"])
    writer.writerow([pk.hex(), sk.hex()])

print("Public and Private keys have been written to xmss_keys.csv")