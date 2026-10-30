Authenticated Diffie-Hellman Key Exchange Protocol Simulator
Finalized 30 October 2026
Written by Colton Olinger

Dependencies:
    pycryptodome 4.2.0
    cryptography 50.0.2

Setup:
    Ensure all files are present in authenticated-dh-key-exchange folder. Open within preferred Python IDE.
    Program through console I/O within IDE. test.py acts as driver file for entire program.
    Files Included:
        authentication.py
        eve.py
        main.py
        modular_math.py
        parameters.py
        participant.py
        protocol.py
        test.py
        README.txt

Running:
    Open and run test.py. Console will prompt user to type in a Test Function. After Test Function is input, user
    will receive another prompt to select a test to perform on the selected function. All options are listed below.
    Test Functions are indented once, tests to perform on selected functions are indented twice.

    quit - must be performed from Test Function prompt; ends program

    exponent - tests for modular_exponentiation function

        known - test comparing known modular exponentiation problem to function output

        expzero - test modular exponentiation with exponent of 0

        modone - test modular exponentiation with modulus of zero

    prime - tests for generate_prime function

        len - test for confirming output bit length matches requested bit length

        odd - test random prime output for oddness

        lib - test if prime is valid prime using library validation function

        size - test for result if bit size input invalid

        bool - test if input type invalid using boolean value False

    mod - tests for received_modulus_validation function

        comp - test output for a composite input value using 32769

        type - test invalid type input using boolean value True

        range - test for received modulus in proper bit length range using 23

    factor - tests for prime_factors function

        1 - test factorization of 1

        22 - test factorization of 22

        repeat - test for return of repeat factors using 65536

    gen - tests for generator_selection function

        23 - test using p=23 as selected prime; expected output 5

        65537 - test using p=65537 as prime; expected output 3

    key - tests for key agreement in full simulated exchange

        23 - test using p=23 as fixed value for prime; removes prime validation to prevent Abort over invalid range

        exchange - test of main_demo using randomly generated prime value and prime validation

    auth - tests for eve attack demos

        unauth - test an unauthenticated exchange MIMA Attack from Eve

        auth - test an authenticated exchange against MIMA Attack from Eve

        A - test for session abort if public dh key value in message modified after authenticated

        prime - test for session abort if prime value in message modified after authenticated

        id - test for session abort if identity in message modified after authenticated

        signed - test for untrusted signature on message received

        response - test for reused authenticated response message in fresh session

        refinish - test for reused authenticated finish message in fresh session

        dupfinish - test for duplicated finish message receipt in same session

    If 'Invalid Input' message is received in response to prompt, check for spelling and case of test requested.
    'Invalid Input' will immediately return to Test Function prompt.