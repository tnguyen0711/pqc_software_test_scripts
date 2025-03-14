import csv


# --- SHA256 Class Definition ---
class SHA256:
    def __init__(self, mode="sha256", verbose=0):
        if mode not in ["sha224", "sha256"]:
            print("Error: Given {} is not a supported mode.".format(mode))
            return
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
        self.k = 0
        self.K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        self.init()

    def init(self):
        if self.mode == "sha256":
            self.H = [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            ]
        else:
            self.H = [
                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
            ]

    def next(self, block):
        self._W_schedule(block)
        self._copy_digest()
        if self.verbose:
            print("State after init:")
            self._print_state(0)
        for i in range(64):
            self._sha256_round(i)
            if self.verbose:
                self._print_state(i)
        self._update_digest()

    def get_digest(self):
        return self.H

    def _copy_digest(self):
        self.a = self.H[0]
        self.b = self.H[1]
        self.c = self.H[2]
        self.d = self.H[3]
        self.e = self.H[4]
        self.f = self.H[5]
        self.g = self.H[6]
        self.h = self.H[7]

    def _update_digest(self):
        self.H[0] = (self.H[0] + self.a) & 0xffffffff
        self.H[1] = (self.H[1] + self.b) & 0xffffffff
        self.H[2] = (self.H[2] + self.c) & 0xffffffff
        self.H[3] = (self.H[3] + self.d) & 0xffffffff
        self.H[4] = (self.H[4] + self.e) & 0xffffffff
        self.H[5] = (self.H[5] + self.f) & 0xffffffff
        self.H[6] = (self.H[6] + self.g) & 0xffffffff
        self.H[7] = (self.H[7] + self.h) & 0xffffffff

    def _print_state(self, round):
        print("State at round 0x{:02x}:".format(round))
        print("t1 = 0x{:08x}, t2 = 0x{:08x}".format(self.t1, self.t2))
        print("k  = 0x{:08x}, w  = 0x{:08x}".format(self.k, self.w))
        print("a  = 0x{:08x}, b  = 0x{:08x}".format(self.a, self.b))
        print("c  = 0x{:08x}, d  = 0x{:08x}".format(self.c, self.d))
        print("e  = 0x{:08x}, f  = 0x{:08x}".format(self.e, self.f))
        print("g  = 0x{:08x}, h  = 0x{:08x}".format(self.g, self.h))
        print("")

    def _sha256_round(self, round):
        self.k = self.K[round]
        self.w = self._next_w(round)
        self.t1 = self._T1(self.e, self.f, self.g, self.h, self.k, self.w)
        self.t2 = self._T2(self.a, self.b, self.c)
        self.h = self.g
        self.g = self.f
        self.f = self.e
        self.e = (self.d + self.t1) & 0xffffffff
        self.d = self.c
        self.c = self.b
        self.b = self.a
        self.a = (self.t1 + self.t2) & 0xffffffff

    def _next_w(self, round):
        if round < 16:
            return self.W[round]
        else:
            tmp_w = (self._delta1(self.W[14]) +
                     self.W[9] +
                     self._delta0(self.W[1]) +
                     self.W[0]) & 0xffffffff
            # Shift the window
            for i in range(15):
                self.W[i] = self.W[i + 1]
            self.W[15] = tmp_w
            return tmp_w

    def _W_schedule(self, block):
        for i in range(16):
            self.W[i] = block[i]

    def _Ch(self, x, y, z):
        return (x & y) ^ (~x & z)

    def _Maj(self, x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    def _sigma0(self, x):
        return self._rotr32(x, 2) ^ self._rotr32(x, 13) ^ self._rotr32(x, 22)

    def _sigma1(self, x):
        return self._rotr32(x, 6) ^ self._rotr32(x, 11) ^ self._rotr32(x, 25)

    def _delta0(self, x):
        return self._rotr32(x, 7) ^ self._rotr32(x, 18) ^ self._shr32(x, 3)

    def _delta1(self, x):
        return self._rotr32(x, 17) ^ self._rotr32(x, 19) ^ self._shr32(x, 10)

    def _T1(self, e, f, g, h, k, w):
        return (h + self._sigma1(e) + self._Ch(e, f, g) + k + w) & 0xffffffff

    def _T2(self, a, b, c):
        return (self._sigma0(a) + self._Maj(a, b, c)) & 0xffffffff

    def _rotr32(self, n, r):
        return ((n >> r) | (n << (32 - r))) & 0xffffffff

    def _shr32(self, n, r):
        return n >> r


# --- Global Helper Functions for SHA-256 ---
def hash_format(input_string):

    if isinstance(input_string, list):
        input_string = hash_unformat(input_string)
    input_string = input_string.encode().hex()
    input_block = []
    # Break the hex string into 8-character (32-bit) chunks
    for i in range(0, len(input_string), 8):
        input_block.append(int("0x" + input_string[i:i + 8], 16))
    # Pad with zeros until there are 16 words
    while len(input_block) < 16:
        input_block.append(0x00000000)
    return input_block[:16]


def hash_unformat(input_array):

    if isinstance(input_array, str):
        return input_array
    return ''.join([f"{x:08x}" for x in input_array])


def F_global(input_string):

    sha = SHA256()
    sha.init()
    formatted = hash_format(input_string)
    sha.next(formatted)
    return sha.get_digest()


def PRF_global(seed, index):

    sha = SHA256()
    sha.init()
    formatted = hash_format(seed)
    sha.next(formatted)
    return sha.get_digest()


def H_global(value):

    sha = SHA256()
    sha.init()
    formatted = hash_format(value)
    sha.next(formatted)
    return sha.get_digest()


def chain_global(X, i, s):

    for _ in range(i, i + s):
        X = F_global(hash_unformat(X))
    return X


def wots_pkGen_global(SK_seed, w, length):

    pubkey_parts = []
    for i in range(length):
        chain = chain_global(PRF_global(SK_seed, str(i)), 0, w - 1)
        pubkey_parts.append(hash_unformat(chain))
    return ''.join(pubkey_parts)


def wots_sign_global(M, SK_seed):

    digest = F_global(M)
    sig_parts = []
    for i in range(32):

        iterations = digest[i % len(digest)] % 16
        chain = chain_global(PRF_global(SK_seed, str(i)), 0, iterations)
        sig_parts.append(hash_unformat(chain))
    return ''.join(sig_parts)


def xmss_node(SK_seed, i, z):

    if z == 0:
        return wots_pkGen_global(SK_seed, 16, 32)
    else:
        left = xmss_node(SK_seed, 2 * i, z - 1)
        right = xmss_node(SK_seed, 2 * i + 1, z - 1)
        return H_global(left + right)


def xmss_sign(M, SK_seed, idx, h=3):

    auth_path = []
    for j in range(h):
        sibling_index = (idx // (2 ** j)) ^ 1
        auth_node = xmss_node(SK_seed, sibling_index, j)
        auth_path.append(auth_node)
    signature = wots_sign_global(M, SK_seed)
    return (signature, auth_path)


# --- Main Function ---
def main():

    input_string = input("Enter the string to hash: ")

    digest = F_global(input_string)
    digest_hex = [f"0x{d:08x}" for d in digest]

    chain_value = chain_global(input_string, 0, 5)
    chain_hex = [f"0x{v:08x}" for v in chain_value]

    wots_key = wots_pkGen_global(input_string, 16, 32)

    xmss_sig = xmss_sign(input_string, input_string, idx=0, h=3)
    wots_sig, auth_path = xmss_sig

    print("\nSHA-256 Digest:")
    print(digest_hex)
    print("\nChain Values:")
    print(chain_hex)
    print("\nWOTS Public Key:")
    print(wots_key)
    print("\nXMSS Signature:")
    print("WOTS Signature:", wots_sig)
    print("Authentication Path:")
    for level, node in enumerate(auth_path):
        print(f"Level {level}: {node}")

    # Write results to a CSV file
    csv_filename = "hash_results.csv"
    with open(csv_filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["SHA-256 Digest", "Chain Values", "WOTS Public Key", "XMSS Signature"])
        writer.writerow([
            " ".join(digest_hex),
            " ".join(chain_hex),
            wots_key,
            str(xmss_sig)
        ])
    print(f"\nResults saved to {csv_filename}")


if __name__ == "__main__":
    main()