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