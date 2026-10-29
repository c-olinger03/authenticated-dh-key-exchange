from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def create_signing_identities():

    alice_private_auth_key = Ed25519PrivateKey.generate()
    alice_public_auth_key = alice_private_auth_key.public_key()

    bob_private_auth_key = Ed25519PrivateKey.generate()
    bob_public_auth_key = bob_private_auth_key.public_key()

    # alice_trusted_auth_keys = {"Bob":bob_public_auth_key}
    #
    # bob_trusted_auth_keys = {"Alice":alice_public_auth_key}

    alice_package = {"alice_private_auth_key" : alice_private_auth_key, "alice_public_auth_key" : alice_public_auth_key,
                     "Bob" : bob_public_auth_key}

    bob_package = {"bob_private_auth_key" : bob_private_auth_key, "bob_public_auth_key" : bob_public_auth_key,
    "Alice" : alice_public_auth_key}

    return alice_package, bob_package

