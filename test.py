from authentication import *
from eve import *
from main import *
from modular_math import *
from parameters import *
from participant import *
from protocol import *

def known_result():
    print("\tExample: 5^6 mod 23")
    print("\tKnown Result: 8")
    print("\tmodular_exponentiation Result:", modular_exponentiation(5, 6, 23))

def exponent_zero():
    print("\tExample: 5^0 mod 23")
    print("\tmodular_exponentiation Result:", modular_exponentiation(5, 0, 23))

def modulus_one():
    print("\tExample: 5^6 mod 1")
    print("\tmodular_exponentiation Result:", modular_exponentiation(5, 6, 1))

def bit_len():
    len = int(input("\tRequested Bit Length: "))
    p = generate_prime(len)
    print("\tBit Length:", p.bit_length())

def oddness():
    p = generate_prime(16)
    oddness = p % 2 != 0
    print("\tOddness:", oddness)

def lib_valid():
    p = generate_prime(16)
    received_modulus_validation(p)

def inval_size():
    p = generate_prime(10)

def inval_bool():
    p = generate_prime(False)

def comp_input():
    received_modulus_validation(32769)

def inval_type():
    received_modulus_validation(True)

def range_check():
    received_modulus_validation(23)

def factor_1():
    factors = prime_factors(1)
    print("\tFactors:", factors)

def factor_22():
    factors = prime_factors(22)
    print("\tFactors:", factors)

def repeat_factors():
    factors = prime_factors(65536)
    print("\tFactors:", factors)

def gen_23():
    print("\tPrime Val: 23")
    p = 23
    factors = prime_factors(p - 1)
    g = generator_selection(p, factors)
    print("\tGenerator Selected:", g)

def gen_65537():
    p = 65537
    factors = prime_factors(p-1)
    g = generator_selection(p, factors)
    print("\tGenerator Selected:", g)

def key_23():
    try:
        # Public Constants Used for Arguments
        PROTOCOL = "DH-CLASSROOM-AUTH-v1"
        ALICE = "Alice"
        BOB = "Bob"

        # Establishing Pre-Authenticated Signatures
        # Instantiating Local Storage for Alice and Bob
        alice_local_package, bob_local_package = create_signing_identities()

        # Alice adds public constant data
        alice_local_package["protocol"] = PROTOCOL
        alice_local_package["initiator"] = ALICE
        alice_local_package["responder"] = BOB
        alice_local_package["init"] = "None"
        alice_local_package["response"] = "None"
        alice_local_package["finish"] = "None"

        # Bob adds public constant data
        bob_local_package["protocol"] = PROTOCOL
        bob_local_package["initiator"] = ALICE
        bob_local_package["responder"] = BOB
        bob_local_package["init"] = "None"
        bob_local_package["response"] = "None"
        bob_local_package["finish"] = "None"

        print("Pre-Established data added to local storage packages.\n")

        # Instantiating Public Network
        public_network = {}

        # ON ALICE LOCAL MACHINE
        print("ON ALICE LOCAL MACHINE:")
        # Generating values for init message to Bob
        p = 23
        p_factors = prime_factors(p - 1)
        g = generator_selection(p, p_factors)
        alice_private_dh_key, alice_public_dh_key = generate_dh_keys(p, g)
        nonce_A = generate_nonce_value()

        # Adding generated values to Alice local storage
        alice_local_package["p"] = p
        alice_local_package["g"] = g
        alice_local_package["A"] = alice_public_dh_key
        alice_local_package["a"] = alice_private_dh_key
        alice_local_package["nonce_A"] = nonce_A

        # Alice preparing public init message to Bob
        A_init_to_B = session_message(alice_local_package["protocol"], "init", alice_local_package["initiator"],
                                      alice_local_package["responder"], alice_local_package["p"], alice_local_package["g"],
                                      alice_local_package["A"], None, alice_local_package["nonce_A"], None)

        # Alice signing init message to Bob
        alice_init_package = sign_message(A_init_to_B, alice_local_package["alice_private_auth_key"])

        # Alice sends init message publicly to Bob
        public_network["alice_init_package"] = alice_init_package
        print("\tAlice init message package sent to public network.\n")

        print("OFF ALICE LOCAL MACHINE\n")
        # OFF ALICE LOCAL MACHINE

        # ON BOB LOCAL MACHINE
        print("ON BOB LOCAL MACHINE:")

        # Bob retrieves Alice init message from public network
        alice_init_package_received = public_network["alice_init_package"]
        print("\tAlice init message package retrieved from public network.\n")

        # Bob verifies Alice's authentication signature on message
        verify_signature(bob_local_package["trusted_key"], alice_init_package_received)

        # Bob decodes init message from Alice
        alice_init_message_received = decode_message(alice_init_package_received)

        # Bob verifies message from Alice
        verify_received_message_package(alice_init_message_received, bob_local_package)

        # Bob stores init values in local storage
        add_received_values(alice_init_message_received, bob_local_package)

        # Bob generates dh keys and nonce value
        bob_private_dh_key, bob_public_dh_key = generate_dh_keys(p, g)
        nonce_B = generate_nonce_value()

        # Bob adds values to local storage
        bob_local_package["b"] = bob_private_dh_key
        bob_local_package["B"] = bob_public_dh_key
        bob_local_package["nonce_B"] = nonce_B

        # Bob prepares public response message to Alice
        B_response_to_A = session_message(bob_local_package["protocol"], "response",
                                          bob_local_package["initiator"], bob_local_package["responder"],
                                          bob_local_package["p"], bob_local_package["g"], bob_local_package["A"],
                                          bob_local_package["B"], bob_local_package["nonce_A"],
                                          bob_local_package["nonce_B"])

        # Bob signing response message to Alice
        bob_response_package = sign_message(B_response_to_A, bob_local_package["bob_private_auth_key"])

        # Bob sends response message publicly to Alice
        public_network["bob_response_package"] = bob_response_package
        print("\tBob response message package sent to public network.\n")

        print("OFF BOB LOCAL MACHINE\n")
        # OFF BOB LOCAL MACHINE

        # ON ALICE LOCAL MACHINE
        print("ON ALICE LOCAL MACHINE:\n")

        # Alice retrieved Bob response message from public network
        bob_response_package_received = public_network["bob_response_package"]
        print("\tBob response message package retrieved from public network.\n")

        # Alice verifies Bob's authentication signature on message
        verify_signature(alice_local_package["trusted_key"], bob_response_package_received)

        # Alice decodes response message from Bob
        bob_response_message_received = decode_message(bob_response_package_received)

        # Alice verifies response message from Bob
        verify_received_message_package(bob_response_message_received, alice_local_package)

        # Alice adds response values to local storage
        add_received_values(bob_response_message_received, alice_local_package)

        # Alice prepares public finish message for Bob
        A_final_to_B = session_message(alice_local_package["protocol"], "finish",
                                       alice_local_package["initiator"], alice_local_package["responder"],
                                       alice_local_package["p"], alice_local_package["g"], alice_local_package["A"],
                                       alice_local_package["B"], alice_local_package["nonce_A"],
                                       alice_local_package["nonce_B"])

        # Alice signs public finish message for Bob
        alice_final_package = sign_message(A_final_to_B, alice_local_package["alice_private_auth_key"])

        # Alice sends final message to Bob on public network
        public_network["alice_final_package"] = alice_final_package
        print("\tAlice final message package sent to public network.\n")

        print("OFF ALICE LOCAL MACHINE\n")
        # OFF ALICE LOCAL MACHINE

        # ON BOB LOCAL MACHINE
        print("ON BOB LOCAL MACHINE:\n")

        # Bob retrieves Alice final message from public network
        alice_final_package_received = public_network["alice_final_package"]
        print("\tAlice final message package retrieved from public network.\n")

        # Bob verifies Alice signature on final package
        verify_signature(bob_local_package["trusted_key"], alice_final_package_received)

        # Bob decodes final message from Alice
        alice_final_message_received = decode_message(alice_final_package_received)

        # Bob retrieves previous transcript of response message for final message verification
        print("\tBob response message retrieved from memory:")
        B_response_to_A_decoded = decode_message(bob_response_package)

        # Bob verifies final message from Alice with previously sent response message
        verify_received_message_package(alice_final_message_received, bob_local_package, B_response_to_A_decoded)

        print("OFF BOB LOCAL MACHINE\n")
        # OFF BOB LOCAL MACHINE

        # ON ALICE LOCAL MACHINE
        print("ON ALICE LOCAL MACHINE:\n")

        # Alice generates secret shared key
        alice_local_package["secret_shared_key"] = get_shared_secret(alice_local_package["B"], alice_local_package["a"],
                                                                     alice_local_package["p"])

        print("OFF ALICE LOCAL MACHINE\n")
        # OFF ALICE LOCAL MACHINE

        # ON BOB LOCAL MACHINE
        print("ON BOB LOCAL MACHINE:\n")
        # Bob generates secret shared key
        bob_local_package["secret_shared_key"] = get_shared_secret(bob_local_package["A"], bob_local_package["b"],
                                                                   bob_local_package["p"])

        print("OFF BOB LOCAL MACHINE\n")
        # OFF BOB LOCAL MACHINE

        # Analysis to confirm matching of secret keys; not a part of the actual exchange; NOT OVER PUBLIC NETWORK
        if alice_local_package["secret_shared_key"] != bob_local_package["secret_shared_key"]:
            raise ValueError("Error: Shared secret mismatch.")

        else:
            print("Shared secret verified.\n")

        print("Authenticated DH Key Exchange successfully completed.")

    except Exception as e:
        print(f"\te")
        print("Key Exchange Aborted.")

def select_test():
    test_function = input("Enter Test Function (See README.txt for Options) (Type 'quit' to Exit): ")

    while test_function != "quit":
        try:
            if test_function == "exponent":
                test_specify = input("Perform Test (See README.txt for Options): ")

                if test_specify == "known":
                    known_result()

                elif test_specify == "expzero":
                    exponent_zero()

                elif test_specify == "modone":
                    modulus_one()

                else:
                    print("Invalid Input")

            elif test_function == "prime":
                test_specify = input("Perform Test (See README.txt for Options): ")

                if test_specify == "len":
                    bit_len()

                elif test_specify == "odd":
                    oddness()

                elif test_specify == "lib":
                    lib_valid()

                elif test_specify == "size":
                    inval_size()

                elif test_specify == "bool":
                    inval_bool()

                else:
                    print("Invalid Input")

            elif test_function == "mod":
                test_specify = input("Perform Test (See README.txt for Options): ")

                if test_specify == "comp":
                    comp_input()

                elif test_specify == "type":
                    inval_type()

                elif test_specify == "range":
                    range_check()

                else:
                    print("Invalid Input")

            elif test_function == "factor":
                test_specify = input("Perform Test (See README.txt for Options): ")

                if test_specify == "1":
                    factor_1()

                elif test_specify == "22":
                    factor_22()

                elif test_specify == "repeat":
                    repeat_factors()

                else:
                    print("Invalid Input")

            elif test_function == "gen":
                test_specify = input("Perform Test (See README.txt for Options): ")

                if test_specify == "23":
                    gen_23()

                elif test_specify == "65537":
                    gen_65537()

                else:
                    print("Invalid Input")

            elif test_function == "key":
                test_specify = input("Perform Test (See README.txt for Options): ")

                if test_specify == "23":
                    key_23()

                elif test_specify == "exchange":
                    main_demo()

                else:
                    print("Invalid Input")

            elif test_function == "auth":
                eve_demo_call()

            else:
                print("Invalid Input")

        except Exception:
            print()

        finally:
            test_function = input("Enter Test Function (See README.txt for Options) (Type 'quit' to Exit): ")

select_test()