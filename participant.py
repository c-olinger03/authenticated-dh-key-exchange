import secrets
from modular_math import modular_exponentiation

# Generate private and public key pair using a prime p and g value as args
def generate_dh_keys(p, g):
    print("\tGenerating DH Keys...")
    # Initialize loop and sentinel value
    keys_generated = False
    while not keys_generated:

        # Random number generation in proper range of p for private key val
        private_key = secrets.randbelow(p-3) + 2

        # Generate public key via modular exponentiation of g by private key
        public_key = modular_exponentiation(g, private_key, p)

        # Break loop if public key in range
        if public_key >= 2 and public_key <= p-2:
            keys_generated = True

    print("\tPrivate Key Generated:", private_key)
    print("\tPublic Key Generated:", public_key)
    print()
    return private_key, public_key

# Generating shared secret key using verified peer public DH key, own private DH key, and verified p
def get_shared_secret(peer_public_dh_key, own_private_dh_key, p):
    print("\tGetting Shared Secret Key ...")

    # For Alice: B^a mod p; for Bob: A^b mod p
    ss_dh_key = modular_exponentiation(peer_public_dh_key, own_private_dh_key, p)
    print("\tShared Secret Key Generated:", ss_dh_key)
    print()
    return ss_dh_key

# Verify received public DH key value is within range for p
def verify_range_peer_public_dh_key(public_dh_key, p):
    print("\tVerifying Range Peer Public DH Key...")

    try:
        # Check if in proper range
        if public_dh_key >=2 and public_dh_key <= p-2:
            print("\tPublic DH Key: Verified")

        else:
            raise ValueError("\tError: Invalid Public DH Key.")

    except ValueError:
        raise Exception("\tAborted at Peer Public DH Key Range Validation.")