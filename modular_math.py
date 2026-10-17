def modular_exponentiation(base, exponent, modulus):

    try:

        if type(base) != int:
            raise TypeError("Base must be an integer.")

        elif type(exponent) != int:
            raise TypeError("Exponent must be an integer.")

        elif type(modulus) != int:
            raise TypeError("Modulus must be an integer.")

        elif exponent < 0:
            raise ValueError("Exponent must be non-negative.")

        elif modulus <= 0:
            raise ValueError("Modulus must be positive.")

        else:
            result = 1 % modulus
            base = base % modulus

            while exponent > 0:
                if exponent % 2 == 1:
                    result = (result * base) % modulus
                base = (base * base) % modulus
                exponent = exponent // 2

            return result

    except (TypeError, ValueError) as e:
        print(e)
        return False