from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def create_signing_identities():

    alice_private_auth_key = Ed25519PrivateKey.generate()
    alice_public_auth_key = alice_private_auth_key.public_key()

    bob_private_auth_key = Ed25519PrivateKey.generate()
    bob_public_auth_key = bob_private_auth_key.public_key()

    alice_package = {"alice_private_auth_key" : alice_private_auth_key, "alice_public_auth_key" : alice_public_auth_key,
                     "trusted_key" : bob_public_auth_key}

    bob_package = {"bob_private_auth_key" : bob_private_auth_key, "bob_public_auth_key" : bob_public_auth_key,
                    "trusted_key" : alice_public_auth_key}

    return alice_package, bob_package

def sign_message(message, private_auth_key):
    signature = private_auth_key.sign(message)
    message_package = (message, signature)
    return message_package

def verify_signature(trusted_key, message_package):
    try:
        trusted_key.verify(message_package[1],message_package[0])
    except InvalidSignature as e:
        print("Invalid Verification Signature. Aborting Exchange")
        return None


