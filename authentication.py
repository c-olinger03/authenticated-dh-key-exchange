from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

# Generates Ed25519 private and public keys, keys in dictionary as packages, returns two packages
def create_signing_identities():

    # generate alice private and public authentication keys
    alice_private_auth_key = Ed25519PrivateKey.generate()
    alice_public_auth_key = alice_private_auth_key.public_key()

    # generate bob private and public authentication keys
    bob_private_auth_key = Ed25519PrivateKey.generate()
    bob_public_auth_key = bob_private_auth_key.public_key()

    # package private, public, and trusted (bob public) keys for alice
    alice_package = {"alice_private_auth_key" : alice_private_auth_key, "alice_public_auth_key" : alice_public_auth_key,
                     "trusted_key" : bob_public_auth_key}

    # package private, public, and trusted (alice public) keys for bob
    bob_package = {"bob_private_auth_key" : bob_private_auth_key, "bob_public_auth_key" : bob_public_auth_key,
                    "trusted_key" : alice_public_auth_key}

    print("Authentication keys generated and packaged.\n")

    # return packages as a tuple
    return alice_package, bob_package

# Sign a message using private authentication key, returns a package containing message and signature
def sign_message(message, private_auth_key):
    print("\tSigning Message...")

    # Uses cryptography library Ed25519 signing method
    signature = private_auth_key.sign(message)

    # Package created with original message and signature
    message_package = (message, signature)
    print("\tMessage package generated and signed.\n")
    return message_package

# Checks signature on message package against trusted key using cryptography library
def verify_signature(trusted_key, message_package):
    print("\tVerifying Signature...")

    try:
        trusted_key.verify(message_package[1],message_package[0])
        print("\tSignature verified.\n")

    except InvalidSignature:
        raise Exception("Invalid Verification Signature.")