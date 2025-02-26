import csv
import hashlib

# Define a SHA-256 class
class SHA256():
    def __init__(self):
        # Initialize SHA-256 hash state values-standard initial values for SHA-256
        self.H = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]

    def hash(self, message):
        # Compute SHA-256 hash of the given message and return it as a hexadecimal string
        return hashlib.sha256(message.encode()).hexdigest()

# Create an instance of the SHA256 class
sha256 = SHA256()

# F Computes SHA-256 hash of the input string
def F(input_string):
    return sha256.hash(input_string)

# PRF hashes a seed connected with an index
def PRF(seed, index):
    return sha256.hash(seed + str(index))

# His  Another wrapper for SHA-256 hash
def H(value):
    return sha256.hash(value)

# Chain function: Applies F iteratively for s times starting from X
def chain(X, i, s):
    tmp = X  # Initialize temporary value with input X
    for _ in range(i, i + s):  # Loop s times
        tmp = F(tmp)  # Apply function F iteratively
    return tmp  # Return final chained value

# WOTS public key generation function
def wots_pkGen(SK_seed, w, length):
    temp = []  # Initialize empty list to store key parts
    for i in range(length):  # Iterate through the given length
        sk = PRF(SK_seed, i)  # Generate private key using PRF
        temp.append(chain(sk, 0, w - 1))  # Compute chain function and store result
    return ''.join(temp)  # Return connected result as public key

# XMSS tree node computation
def xmss_node(SK_seed, i, z):
    if z == 0:
        return wots_pkGen(SK_seed, 16, 32)  # Generate WOTS public key at leaf node
    else:
        lnode = xmss_node(SK_seed, 2 * i, z - 1)  # Compute left subtree node
        rnode = xmss_node(SK_seed, 2 * i + 1, z - 1)  # Compute right subtree node
        return H(lnode + rnode)  # Hash connected left and right nodes

# XMSS signature generation function
def xmss_sign(M, SK_seed, idx, h=10):
    AUTH = []  # Initialize authentication path list
    for j in range(h):  # Iterate over tree height
        k = (idx // (2 ** j)) ^ 1  # Compute sibling node index
        AUTH.append(xmss_node(SK_seed, k, j))  # Store authentication node
    sig = [F(str(M) + str(i)) for i in range(10)]  # Generate signature using F function
    return (sig, AUTH)  # Return signature and authentication path

# Main function
def main():
    input_string = input("Enter a string: ")  # Take user input
    SK_seed = sha256.hash(input_string)  # Compute seed from input string
    idx = int(hashlib.sha256(input_string.encode()).hexdigest(), 16) % (2 ** 10)  # Compute index from hash

    M = int(sha256.hash(input_string), 16) % (2 ** 256)  # Compute message hash modulo 2^256

    pub_key = xmss_node(SK_seed, 0, 10)  # Generate XMSS public key
    SIG_XMSS = xmss_sign(M, SK_seed, idx)  # Generate XMSS signature
    sig_str = ' '.join(SIG_XMSS[0])  # Convert signature list to string
    auth_str = ' '.join(SIG_XMSS[1])  # Convert authentication path list to string
    formatted_sig = f"{sig_str} {auth_str}"  # Concatenate signature and authentication path

    # Write the output to a CSV file
    with open("xmss_output.csv", "w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Input String", "Public Key", "XMSS Signature"])  # Write headers
        writer.writerow([input_string, pub_key, formatted_sig])  # Write computed values

# Run main function if script is executed directly
if __name__ == "__main__":
    main()
