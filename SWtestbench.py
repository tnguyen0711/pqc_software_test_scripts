import csv
import hashlib


class ADRS:
    def __init__(self):
        self.a = bytearray(32)

    def set_layer_address(self, x):
        self.a[0:4] = x.to_bytes(4, byteorder='big')

    def set_key_pair_address(self, x):
        self.a[20:24] = x.to_bytes(4, byteorder='big')

    def get_key_pair_address(self):
        return int.from_bytes(self.a[20:24], byteorder='big')

    def set_tree_index(self, x):
        self.a[28:32] = x.to_bytes(4, byteorder='big')

    def set_tree_height(self, h):
        self.a[24:28] = h.to_bytes(4, byteorder='big')

    def set_type_and_clear(self, t):
        """ Set type of ADRS and clear last 12 bytes."""
        self.a[16:20] = t.to_bytes(4, byteorder='big')
        for i in range(12):
            self.a[20 + i] = 0

    def copy(self):
        """ Return a copy of ADRS object."""
        new_adrs = ADRS()
        new_adrs.a = self.a[:]
        return new_adrs


class XMSS:
    WOTS_HASH = 0
    WOTS_PRF = 1
    WOTS_PK = 2
    TREE = 3

    def __init__(self, w, hp, d, length):
        self.w = w
        self.hp = hp
        self.d = d
        self.len = length

    def prf(self, pk_seed, sk_seed, adrs):
        """ PRF function using SHA256 HMAC."""
        input_data = sk_seed + pk_seed + adrs.a
        return hashlib.sha256(input_data).digest()

    def h_t(self, pk_seed, adrs, tmp):
        """ Hash function for public key generation using SHA256."""
        input_data = pk_seed + adrs.a + tmp
        return hashlib.sha256(input_data).digest()

    def h_h(self, pk_seed, adrs, lnode_rnode):
        """ Hash function for node generation using SHA256."""
        input_data = pk_seed + adrs.a + lnode_rnode
        return hashlib.sha256(input_data).digest()

    def chain(self, sk, start, stop, pk_seed, adrs):
        """ Chain function based on iterative hash applications."""
        tmp = sk
        for j in range(start, stop + 1):
            adrs.set_tree_index(j)
            tmp = self.prf(pk_seed, tmp, adrs)
        return tmp

    def wots_pkgen(self, sk_seed, pk_seed, adrs):
        """ Generate a WOTS+ public key."""
        sk_adrs = adrs.copy()
        sk_adrs.set_type_and_clear(self.WOTS_PRF)
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        tmp = b''
        for i in range(self.len):
            sk_adrs.set_tree_index(i)
            sk = self.prf(pk_seed, sk_seed, sk_adrs)
            adrs.set_tree_index(i)
            tmp += self.chain(sk, 0, self.w - 1, pk_seed, adrs)
        wotspk_adrs = adrs.copy()
        wotspk_adrs.set_type_and_clear(self.WOTS_PK)
        wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        pk = self.h_t(pk_seed, wotspk_adrs, tmp)
        return pk

    def xmss_node(self, sk_seed, i, z, pk_seed, adrs):
        """ Compute the root of a Merkle subtree of WOTS+ public keys."""
        if z > self.hp or i >= 2 ** (self.hp - z):
            return None
        if z == 0:
            adrs.set_type_and_clear(self.WOTS_HASH)
            adrs.set_key_pair_address(i)
            node = self.wots_pkgen(sk_seed, pk_seed, adrs)
        else:
            lnode = self.xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
            rnode = self.xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
            adrs.set_type_and_clear(self.TREE)
            adrs.set_tree_height(z)
            adrs.set_tree_index(i)
            node = self.h_h(pk_seed, adrs, lnode + rnode)
        return node

    def slh_keygen_internal(self, sk_seed, sk_prf, pk_seed):
        """ Generate SLH public and private key pair."""
        adrs = ADRS()
        adrs.set_layer_address(self.d - 1)
        pk_root = self.xmss_node(sk_seed, 0, self.hp, pk_seed, adrs)
        sk = sk_seed + sk_prf + pk_seed + pk_root
        pk = pk_seed + pk_root
        return pk, sk


# Test bench to output keys to a CSV file
def test_bench():
    # Parameters for testing
    sk_seed = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    sk_prf = b'\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10'
    pk_seed = b'\x11\x12\x13\x14\x15\x16\x17\x18'

    # Instantiate XMSS class with w=16, hp=5, d=1, len=4 for testing
    xmss = XMSS(w=16, hp=5, d=1, length=4)

    # Generate keys
    pk, sk = xmss.slh_keygen_internal(sk_seed, sk_prf, pk_seed)

    # Write to CSV
    with open('keys.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Public Key', 'Private Key'])
        writer.writerow([pk.hex(), sk.hex()])

    print(f"Public Key: {pk.hex()}")
    print(f"Private Key: {sk.hex()}")


# Run the test bench
test_bench()