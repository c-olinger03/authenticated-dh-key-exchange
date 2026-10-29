from Crypto.Util.number import getPrime, isPrime
import secrets
import time

from modular_math import modular_exponentiation


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

        if type(bits) != int:
            raise TypeError("Bits must be an integer.")

        elif bits < 16 or bits > 32:
            raise ValueError("Bits must be between 16 and 32 inclusive.")

        else:
            p_found = False

            while not p_found:
                p = getPrime(bits, secrets.token_bytes)

                if p % 2 != 0 and p.bit_length() == bits:
                    p_found = True

            return p

    except (TypeError, ValueError) as e:
        print(e)
        return False

def received_modulus_validation(modulus):
    try:
        if type(modulus) != int:
            raise TypeError("Modulus must be an integer.")

        elif modulus.bit_length() < 16 or modulus.bit_length() > 32:
            raise ValueError(f"Modulus must be between 16-bits and 32-bits inclusive in length.")

        else:
            if isPrime(modulus):
                return True

            else:
                raise ValueError("Modulus is not a prime number.")

    except (TypeError, ValueError) as e:
        print(e)
        return False

def prime_factors(n):
    try:
        if type(n) != int:
            raise TypeError("n must be an integer.")

        elif n < 1:
            raise ValueError("n must be a positive integer.")

        elif n == 1:
            return set()

        else:

            distinct_factors = set()

            if n % 2 == 0:
                distinct_factors.add(2)
                while n % 2 == 0:
                    n //= 2

            odd_divisor = 3

            while odd_divisor * odd_divisor < n:

                if n % odd_divisor == 0:
                    distinct_factors.add(odd_divisor)
                    while n % odd_divisor == 0:
                        n //= odd_divisor

                odd_divisor += 2

            if n > 1:
                distinct_factors.add(n)

            return distinct_factors


    except (TypeError, ValueError) as e:
        print(e)
        return False

def generator_selection(p, factors):

    g = 2

    generator_found = False

    while not generator_found:

        generator_found = True

        for r in factors:
            test_candidate = modular_exponentiation(g, (p-1) // r, p)
            if test_candidate == 1:
                generator_found = False

        if not generator_found:
            g += 1
            if g == p-1:
                return False

    return g