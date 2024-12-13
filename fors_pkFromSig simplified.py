def fors_pk_from_sig(self, sig_fors, md):
    """ Simplified Algorithm 17: fors_pkFromSig
    Compute a FORS public key from a FORS signature.
    """

    def get_sk(sig_fors, i):
        """ Extract the secret key for a given index. """
        return sig_fors[i * (self.a + 1) * self.n:(i * (self.a + 1) + 1) * self.n]

    def get_auth(sig_fors, i):
        """ Extract the authentication path for a given index. """
        return sig_fors[(i * (self.a + 1) + 1) * self.n:(i + 1) * (self.a + 1) * self.n]

    indices = self.base_2b(md, self.a, self.k)  # Derive indices from the message digest

    root = b''
    for i in range(self.k):
        sk = get_sk(sig_fors, i)  # Extract the secret key
        node_0 = self.h_f(sk)  # Compute the leaf node using the secret key

        auth = get_auth(sig_fors, i)  # Get the authentication path
        for j in range(self.a):
            auth_j = auth[j * self.n:(j + 1) * self.n]
            if (indices[i] >> j) & 1 == 0:
                node_1 = self.h_h(node_0 + auth_j)  # Combine current node and auth path
            else:
                node_1 = self.h_h(auth_j + node_0)  # Reverse order for sibling node
            node_0 = node_1  # Update the current node

        root += node_0  # Accumulate root nodes for all FORS trees

    # Compute the FORS public key as the hash of the aggregated roots
    pk = self.h_t(root)
    return pk