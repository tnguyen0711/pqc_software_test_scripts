def wots_pkgen(self, sk_seed):
    """ Simplified Algorithm 6: wots_PKgen(SK.seed, PK.seed, ADRS).
        Generate a WOTS+ public key."""
    tmp = b''
    for i in range(self.len):
        # Generate the secret key element for the i-th chain
        sk = self.prf(sk_seed, i)
        # Compute the chain to generate the i-th public key element
        tmp += self.chain(sk, 0, self.w - 1)

    # Compute the WOTS+ public key as the hash of the public key elements
    pk = self.h_t(tmp)
    return pk