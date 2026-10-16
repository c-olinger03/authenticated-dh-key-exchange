import cryptography
from Crypto.Util.number import getPrime, isPrime
import secrets
import time


def timer_and_value(func):
    def inner(*args, **kwargs):
        start_time = time.perf_counter()

        value = func(*args, **kwargs)

        end_time = time.perf_counter()

        execution_time = end_time - start_time

        return value, execution_time

    return inner

@timer_and_value
def generate_prime(bits):
    try:

        # Add messages for TypeError
        if type(bits) != int:
            raise TypeError

        # Add messages for ValueError
        elif bits < 16 or bits > 32:
            raise ValueError

        else:
            p_found = False

            while not p_found:
                p = getPrime(bits, secrets.token_bytes)

                if isPrime(p) and p.bit_length() == bits:
                    p_found = True

            return p

    # Add exception conditions
    except (TypeError, ValueError):
        pass