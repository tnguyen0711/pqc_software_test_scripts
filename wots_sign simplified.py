def wots_sign(self, m, sk_seed):
    """ Simplified Algorithm 7: wots_sign(M, SK.seed, PK.seed, ADRS).
        Generate a WOTS+ signature on an n-byte message."""
    csum = 0
    # Compute the message in base `w` and calculate the checksum
    msg = self.base_2b(m, self.lg_w, self.len1)
    for i in range(self.len1):
        csum += self.w - 1 - msg[i]
    csum <<= ((8 - ((self.len2 * self.lg_w) % 8)) % 8)
    msg += self.base_2b(self.to_byte(csum,
                                     (self.len2 * self.lg_w + 7) // 8), self.lg_w, self.len2)

    # Generate the WOTS+ signature
    sig = b''
    for i in range(self.len):
        # Generate the secret key element for the i-th chain
        sk = self.prf(sk_seed, i)
        # Compute the hash chain up to msg[i]
        sig += self.chain(sk, 0, msg[i])

    return sig