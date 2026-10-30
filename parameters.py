from Crypto.Util.number import getPrime, isPrime
import secrets
import time
from modular_math import modular_exponentiation

# Timer wrapper for functions
def timer(func):
    def inner(*args, **kwargs):
        start_time = time.perf_counter()

        value = func(*args, **kwargs)

        end_time = time.perf_counter()

        execution_time = end_time - start_time

        print(f"\tTime Taken: {execution_time:.6f} seconds\n")
        return value
    return inner


@timer
# Generates prime number with (bits) number of bits
def generate_prime(bits):
    print("\tGenerating Prime...")

    try:

        # Verifying bits type & value
        if type(bits) != int:
            raise TypeError("\tError: Bits must be an integer.")

        print("\tBit Input:", bits)

        if bits < 16 or bits > 32:
            raise ValueError("\tError: Bits must be between 16 and 32 inclusive.")

        # Initialize loop & sentinel value
        p_found = False
        while not p_found:

            # Generate a (bits) bitlength prime
            p = getPrime(bits, secrets.token_bytes)

            # Verify prime is not even and has (bits) bits.
            if p % 2 != 0 and p.bit_length() == bits:

                # Break loop
                p_found = True

        print("\tPrime Generated:", p)
        return p

    # Reject Value, Abort Exchange
    except TypeError, ValueError:
        raise Exception("Aborted at Prime Generation.")

# Verify valid prime modulus received
def received_modulus_validation(modulus):
    print("\tModulus Validation...")

    try:
        # Verify type and size of modulus
        if type(modulus) != int:
            raise TypeError("\tError:Modulus must be an integer.")

        if modulus.bit_length() < 16 or modulus.bit_length() > 32:
            raise ValueError("\tError: Modulus must be between 16-bits and 32-bits inclusive in length.")

        # Check modulus for primality using Crypto library isPrime method
        if isPrime(modulus):
            print("\tModulus: Verified")

        else:
            raise ValueError("Error: Modulus is not a prime number.")

    # Reject Value, Abort Exchange
    except TypeError, ValueError:
        raise Exception("Aborted at Modulus Validation.")


@timer
# Find unique prime factors of n.
def prime_factors(n):
    print("\tFactoring n...")

    try:

        # Verify n type and value
        if type(n) != int:
            raise TypeError("\tError: n must be an integer.")
        if n < 1:
            raise ValueError("\tError: n must be a positive integer.")

        # If n == 1, return empty set
        if n == 1:
            print("\tFactor Set: Empty")
            return set()

        else:
            distinct_factors = set()

            # Divide n by 2 evenly until no longer possible, store 2 in set
            if n % 2 == 0:
                distinct_factors.add(2)
                while n % 2 == 0:
                    n //= 2


            odd_divisor = 3
            while odd_divisor * odd_divisor < n:

                # Divide n by odd divisor evenly until no longer possible, store odd divisor in set
                if n % odd_divisor == 0:
                    distinct_factors.add(odd_divisor)
                    while n % odd_divisor == 0:
                        n //= odd_divisor

                # Increment to next odd value
                odd_divisor += 2

            # Add remainder to set
            if n > 1:
                distinct_factors.add(n)

            print("\tFactor Set:", distinct_factors)
            return distinct_factors

    # Reject Value, Abort Exchange
    except TypeError, ValueError:
        raise Exception("Aborted at Prime Factorization.")

@timer
# Generate g value for dh key generation; p and factors of p-1 as args; return int g
def generator_selection(p, factors):
    print("\tSelecting Generator...")

    try:

        # Verify type of args
        if type(p) != int:
            raise TypeError("\tError: p must be an integer.")
        if type(factors) != set:
            raise TypeError("\tError: expected factors in set.")

        g = 2

        # Initialize loop and sentinel value
        generator_found = False
        while not generator_found:

            # Break loop if not changed by end of loop
            generator_found = True

            # Test g candidate for modular exponentiation with each val of factors
            for r in factors:
                test_candidate = modular_exponentiation(g, (p-1) // r, p)

                # Set sentinel value for another iteration of outer loop
                if test_candidate == 1:
                    generator_found = False

            # Increment g if next iteration needed
            if not generator_found:
                g += 1

                # Check if g in range
                if g == p-1:
                    raise ValueError("\tError: No Generator Found.")

        print("\tGenerator Selected:", g)
        return g

    # Reject Value, Abort Exchange
    except TypeError, ValueError:
        raise Exception("Aborted at Generator Selection.")

# Verify generator value of prime
def received_generator_validation(provided_g, p):
    print("\tGenerator Validation...")

    try:
        # Find factors of p-1
        p_factors = prime_factors(p-1)

        # call generator selection method
        calculated_g = generator_selection(p, p_factors)

        # Verify calculated generator matches provided generator
        if calculated_g == provided_g:
            print("\tGenerator: Validated")

        else:
            raise ValueError("Error: Generator is not valid.")

    except TypeError, ValueError:
        raise Exception("Aborted at Generator Validation.")