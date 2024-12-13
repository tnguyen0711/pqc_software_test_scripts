def fors_sign(self, md, sk_seed):
    """ Simplified Algorithm 16: fors_sign
    Generate a FORS signature."""
    sig_fors = b''
    indices = self.base_2b(md, self.a, self.k)  # Calculate indices from the message digest

    for i in range(self.k):
        # Generate the secret key for the given index
        sig_fors += self.fors_sk_gen(sk_seed, (i << self.a) + indices[i])

        # Build the authentication path for the current index
        for j in range(self.a):
            s = (indices[i] >> j) ^ 1
            sig_fors += self.fors_node(sk_seed, (i << (self.a - j)) + s, j)

    return sig_fors