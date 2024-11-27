def xmss_sign(self, m, sk_seed, idx):
    """ Simplified XMSS signature generation. """
    auth = b''
    for j in range(self.hp):
        k = (idx >> j) ^ 1
        auth += self.xmss_node(sk_seed, k, j)
    sig = self.wots_sign(m, sk_seed)
    sig_xmss = sig + auth
    return sig_xmss