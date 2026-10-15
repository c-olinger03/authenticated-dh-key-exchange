def modular_exponentiation(base, exponent, modulus):

    try:

        # Add messages for specific TypeError points
        if type(base) != int or type(exponent) != int or type(modulus) != int:
            raise TypeError

        # Add messages for specific ValueError points
        elif exponent < 0 or modulus <= 0:
            raise ValueError

        else:
            result = 1 % modulus
            base = base % modulus

            while exponent > 0:
                if exponent % 2 == 1:
                    result = (result * base) % modulus
                base = (base * base) % modulus
                exponent = exponent // 2

            return result


    # Add exception conditions
    except (TypeError, ValueError):
        pass