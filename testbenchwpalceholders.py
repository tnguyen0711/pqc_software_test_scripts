import csv
import hashlib

class ADRS:
    def __init__(self):
        self.layer_address = 0

    def set_layer_address(self, layer):
        self.layer_address = layer

# Function to generate a hash (used as a placeholder for xmss_node)
def hash_function(data):
    """ Hashes input data using SHA-256 """
    return hashlib.sha256(data.encode()).hexdigest()

# Function simulating the XMSS node (this is a placeholder, replace with actual logic)
def xmss_node(sk_seed, start_idx, hp, pk_seed, adrs):
    """
    This function would normally compute the XMSS node based on the secret key seed,
    height, pk_seed, and address. Here, we're using a hash function to simulate this.
    """
    # Combining inputs to simulate node creation (for testing purposes)
    combined = sk_seed + pk_seed + str(start_idx) + str(hp) + str(adrs.layer_address)
    return hash_function(combined)

# Main test class that includes slh_keygen_internal function
class TestBench:
    def __init__(self, d, hp):
        self.d = d
        self.hp = hp

    def slh_keygen_internal(self, sk_seed, sk_prf, pk_seed):
        """ Algorithm 18: slh_keygen_internal()."""
        adrs = ADRS()
        adrs.set_layer_address(self.d - 1)
        pk_root = xmss_node(sk_seed, 0, self.hp, pk_seed, adrs)
        sk = sk_seed + sk_prf + pk_seed + pk_root
        pk = pk_seed + pk_root
        return pk, sk

# Function to write keys to CSV
def write_to_csv(filename, pk, sk):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Public Key', 'Private Key'])
        writer.writerow([pk, sk])

# Test function
def main():
    # Non-random deterministic seeds for testing purposes
    sk_seed = "SKSEED1234567890"
    sk_prf = "SKPRF1234567890"
    pk_seed = "PKSEED1234567890"

    # Create a TestBench instance
    testbench = TestBench(d=4, hp=10)

    # Run key generation
    pk, sk = testbench.slh_keygen_internal(sk_seed, sk_prf, pk_seed)

    # Output the keys to a CSV file
    write_to_csv('key_output.csv', pk, sk)

    print(f"Keys have been written to key_output.csv\nPublic Key: {pk}\nPrivate Key: {sk}")

if __name__ == "__main__":
    main()