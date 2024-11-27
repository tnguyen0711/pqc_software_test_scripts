def xmss_pk_from_sig(self, idx, sig_xmss, m):
    """ Compute an XMSS public key from an XMSS signature."""
    sig = sig_xmss[0:self.len * self.n]
    auth = sig_xmss[self.len * self.n:]

    node_0 = self.wots_pk_from_sig(sig, m)

    for k in range(self.hp):
        auth_k = auth[k * self.n:(k + 1) * self.n]
        if (idx >> k) & 1 == 0:
            node_1 = self.h_h(node_0 + auth_k)
        else:
            node_1 = self.h_h(auth_k + node_0)
        node_0 = node_1

    return node_0