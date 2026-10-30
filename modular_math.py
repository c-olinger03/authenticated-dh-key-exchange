# Performs modular exponentiation more efficiently than pow() by squaring repeatedly instead of multiplying
#   which achieved end result faster
def modular_exponentiation(base, exponent, modulus):

    try:

        if type(base) != int:
            raise TypeError("Error: Base must be an integer.")

        if type(exponent) != int:
            raise TypeError("Error: Exponent must be an integer.")

        if type(modulus) != int:
            raise TypeError("Error: Modulus must be an integer.")

        if exponent < 0:
            raise ValueError("Error: Exponent must be non-negative.")

        if modulus <= 0:
            raise ValueError("Error: Modulus must be positive.")

        # Initialize result to 1
        result = 1 % modulus

        # Initialized base
        base = base % modulus

        # Continues until exponent is fully decremented via floor div
        while exponent > 0:

            # Catch if squaring would result in excess value; sets final result; multiply by base then mod
            if exponent % 2 == 1:
                result = (result * base) % modulus

            # Square base then mod
            base = (base * base) % modulus

            # Exponent halved
            exponent = exponent // 2

        # Return final
        return result

    # Invalid argument, Abort Exchange
    except (TypeError, ValueError):
        raise Exception("Aborted at Modular Exponentiation.")