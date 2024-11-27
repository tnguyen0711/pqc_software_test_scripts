def xmss_node(self, sk_seed, i, z):
    """ Simplified XMSS Node: Compute the root of a Merkle subtree of WOTS+ public keys.
        Inputs: sk_seed, i, z."""
    if z > self.hp or i >= 2**(self.hp - z):
        return None
    if z == 0:
        node = self.wots_pkgen(sk_seed)
    else:
        lnode = self.xmss_node(sk_seed, 2 * i, z - 1)
        rnode = self.xmss_node(sk_seed, 2 * i + 1, z - 1)
        node = self.h_h(sk_seed, lnode + rnode)
    return node
