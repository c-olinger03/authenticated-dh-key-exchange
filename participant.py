import secrets
from modular_math import modular_exponentiation


def generate_dh_keys(p, g):
    keys_generated = False

    while not keys_generated:
        private_key = secrets.randbelow(p-3) + 2

        public_key = modular_exponentiation(g, private_key, p)

        if public_key >= 2 and public_key <= p-2:
            keys_generated = True

    return private_key, public_key

def get_shared_secret(peer_public_dh_key, own_private_dh_key, p):
    ss_dh_key = modular_exponentiation(peer_public_dh_key, own_private_dh_key, p)
    return ss_dh_key

def verify_range_peer_public_dh_key(public_dh_key, p):
    if public_dh_key >=2 and public_dh_key <= p-2:
        return public_dh_key
    else:
        raise Exception("Invalid Public DH Key")