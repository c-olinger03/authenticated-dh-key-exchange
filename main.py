from participant import *
from parameters import *
from authentication import *
from protocol import *

def main():
    try:
        # Public Constants Used for Arguments
        PROTOCOL = "DH-CLASSROOM-AUTH-v1"
        DH_KEY_BIT_LEN = 16
        ALICE = "Alice"
        BOB = "Bob"

        # Establishing Pre-Authenticated Signatures
        # Instantiating Local Storage for Alice and Bob
        alice_local_package, bob_local_package = create_signing_identities()

        # Alice adds public constant data
        alice_local_package["protocol"] = PROTOCOL
        alice_local_package["initiator"] = ALICE
        alice_local_package["responder"] = BOB

        # Bob adds public constant data
        bob_local_package["protocol"] = PROTOCOL
        bob_local_package["initiator"] = ALICE
        bob_local_package["responder"] = BOB

        print("Pre-Established data added to local storage packages.\n")

        # Instantiating Public Network
        public_network = {}

        # ON ALICE LOCAL MACHINE
        print("ON ALICE LOCAL MACHINE:")
        # Generating values for init message to Bob
        p = generate_prime(DH_KEY_BIT_LEN)
        p_factors = prime_factors(p-1)
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

    except Exception:
        print("Key Exchange Aborted.")

if __name__ == "__main__":
    main()

