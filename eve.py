from participant import *
from parameters import *
from authentication import *
from protocol import *

# Simulate Eve MIMA attack on unauthenticated DH key exchange
def unauth_eve_demo():
    try:
        # Public Constants Used for Arguments
        PROTOCOL = "DH-CLASSROOM-AUTH-v1"
        DH_KEY_BIT_LEN = 16
        ALICE = "Alice"
        BOB = "Bob"

        alice_local_package = {}
        bob_local_package = {}
        eve_local_package_for_alice= {}
        eve_local_package_for_bob = {}

        # Alice adds public constant data
        alice_local_package["protocol"] = PROTOCOL
        alice_local_package["initiator"] = ALICE
        alice_local_package["responder"] = BOB
        alice_local_package["init"]= "None"
        alice_local_package["response"]= "None"
        alice_local_package["finish"]= "None"

        # Bob adds public constant data
        bob_local_package["protocol"] = PROTOCOL
        bob_local_package["initiator"] = ALICE
        bob_local_package["responder"] = BOB
        bob_local_package["init"]= "None"
        bob_local_package["response"]= "None"
        bob_local_package["finish"]= "None"

        # Eve adds public constant data
        eve_local_package_for_alice["protocol"] = PROTOCOL
        eve_local_package_for_alice["initiator"] = ALICE
        eve_local_package_for_alice["responder"] = BOB
        eve_local_package_for_alice["init"]= "None"
        eve_local_package_for_alice["response"]= "None"
        eve_local_package_for_alice["finish"]= "None"

        eve_local_package_for_bob["protocol"] = PROTOCOL
        eve_local_package_for_bob["initiator"] = ALICE
        eve_local_package_for_bob["responder"] = BOB
        eve_local_package_for_bob["init"]= "None"
        eve_local_package_for_bob["response"]= "None"
        eve_local_package_for_bob["finish"]= "None"


        print("Pre-Established data added to local storage packages.\n")

        # Instantiating Public Networks
        public_network_eve_alice = {}
        public_network_eve_bob = {}

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

        # Alice preparing public init message to Bob (Eve)
        A_init_to_B = session_message(alice_local_package["protocol"], "init", alice_local_package["initiator"],
                                      alice_local_package["responder"], alice_local_package["p"], alice_local_package["g"],
                                      alice_local_package["A"], None, alice_local_package["nonce_A"], None)

        # Alice unsigned init package
        alice_init_package = (A_init_to_B, None)

        # Alice sends init message publicly to Bob (Eve)
        public_network_eve_alice["alice_init_package"] = alice_init_package
        print("\tAlice init message package sent to public network.\n")

        print("OFF ALICE LOCAL MACHINE\n")
        # OFF ALICE LOCAL MACHINE

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:")

        print("\tEVE FORGING RESPONSE FOR ALICE:\n")
        # Eve retrieves Alice init message from public network
        alice_init_package_received = public_network_eve_alice["alice_init_package"]
        print("\tAlice init message package retrieved from public network.\n")

        # Eve decodes init message from Alice
        alice_init_message_received_eve = decode_message(alice_init_package_received)

        # Eve verifies message from Alice
        verify_received_message_package(alice_init_message_received_eve, eve_local_package_for_alice)

        # Eve stores init values in local storage
        add_received_values(alice_init_message_received_eve, eve_local_package_for_alice)

        # Eve copies p and g to local package for Bob
        eve_local_package_for_bob["p"] = eve_local_package_for_alice["p"]
        eve_local_package_for_bob["g"] = eve_local_package_for_alice["g"]

        # Eve generates dh keys and nonce value
        eve_bob_private_dh_key, eve_bob_public_dh_key = generate_dh_keys(p, g)
        eve_nonce_B = generate_nonce_value()

        # Eve adds values to local storage
        eve_local_package_for_alice["b"] = eve_bob_private_dh_key
        eve_local_package_for_alice["B"] = eve_bob_public_dh_key
        eve_local_package_for_alice["nonce_B"] = eve_nonce_B

        # Eve prepares public response message to Alice
        B_response_to_A_eve = session_message(eve_local_package_for_alice["protocol"], "response",
                                          eve_local_package_for_alice["initiator"], eve_local_package_for_alice["responder"],
                                          eve_local_package_for_alice["p"], eve_local_package_for_alice["g"], eve_local_package_for_alice["A"],
                                          eve_local_package_for_alice["B"], eve_local_package_for_alice["nonce_A"],
                                          eve_local_package_for_alice["nonce_B"])

        # Eve unsigned response package.
        bob_response_package_eve = (B_response_to_A_eve, None)

        # Eve sends response message publicly to Alice
        public_network_eve_alice["bob_response_package"] = bob_response_package_eve
        print("\tEve response message package sent to public network.\n")

        print("\tFORGING INIT MESSAGE FOR BOB:")
        # Generating values for init message to Bob
        eve_alice_private_dh_key, eve_alice_public_dh_key = generate_dh_keys(p, g)
        eve_nonce_A = generate_nonce_value()

        # Adding generated values to Eve local storage
        eve_local_package_for_bob["A"] = eve_alice_public_dh_key
        eve_local_package_for_bob["a"] = eve_alice_private_dh_key
        eve_local_package_for_bob["nonce_A"] = eve_nonce_A

        # Eve preparing public init message to Bob
        A_init_to_B_eve = session_message(eve_local_package_for_bob["protocol"], "init", eve_local_package_for_bob["initiator"],
                                      eve_local_package_for_bob["responder"], eve_local_package_for_bob["p"],
                                      eve_local_package_for_bob["g"],
                                      eve_local_package_for_bob["A"], None, eve_local_package_for_bob["nonce_A"], None)

        # Eve unsigned init package
        alice_init_package_eve = (A_init_to_B_eve, None)

        # Eve sends init message publicly to Bob
        public_network_eve_bob["alice_init_package"] = alice_init_package_eve
        print("\tAlice init message package sent to public network.\n")

        print("OFF EVE LOCAL MACHINE\n")
        # OFF EVE LOCAL MACHINE

        # ON BOB LOCAL MACHINE
        print("ON BOB LOCAL MACHINE:")

        # Bob retrieves Alice (Eve) init message from public network
        alice_init_package_received = public_network_eve_bob["alice_init_package"]
        print("\tAlice init message package retrieved from public network.\n")

        # Bob decodes init message from Alice (Eve)
        alice_init_message_received = decode_message(alice_init_package_received)

        # Bob verifies message from Alice (Eve)
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

        # Bob prepares public response message to Alice (Eve)
        B_response_to_A = session_message(bob_local_package["protocol"], "response",
                                          bob_local_package["initiator"], bob_local_package["responder"],
                                          bob_local_package["p"], bob_local_package["g"], bob_local_package["A"],
                                          bob_local_package["B"], bob_local_package["nonce_A"],
                                          bob_local_package["nonce_B"])

        # Bob unsigned response message to Alice (Eve)
        bob_response_package = (B_response_to_A, None)

        # Bob sends response message publicly to Alice (Eve)
        public_network_eve_bob["bob_response_package"] = bob_response_package
        print("\tBob response message package sent to public network.\n")

        print("OFF BOB LOCAL MACHINE\n")
        # OFF BOB LOCAL MACHINE

        # ON ALICE LOCAL MACHINE
        print("ON ALICE LOCAL MACHINE:\n")

        # Alice retrieved Bob (Eve) response message from public network
        bob_response_package_received = public_network_eve_alice["bob_response_package"]
        print("\tBob response message package retrieved from public network.\n")

        # Alice decodes response message from Bob (Eve)
        bob_response_message_received = decode_message(bob_response_package_received)

        # Alice verifies response message from Bob (Eve)
        verify_received_message_package(bob_response_message_received, alice_local_package)

        # Alice adds response values to local storage
        add_received_values(bob_response_message_received, alice_local_package)

        # Alice prepares public finish message for Bob (Eve)
        A_final_to_B = session_message(alice_local_package["protocol"], "finish",
                                       alice_local_package["initiator"], alice_local_package["responder"],
                                       alice_local_package["p"], alice_local_package["g"], alice_local_package["A"],
                                       alice_local_package["B"], alice_local_package["nonce_A"],
                                       alice_local_package["nonce_B"])

        # Alice unsigned public finish message for Bob (Eve)
        alice_final_package = (A_final_to_B, None)

        # Alice sends final message to Bob (Eve) on public network
        public_network_eve_alice["alice_final_package"] = alice_final_package
        print("\tAlice final message package sent to public network.\n")

        print("OFF ALICE LOCAL MACHINE\n")
        # OFF ALICE LOCAL MACHINE

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:")

        print("\tEVE VERIFICATION ALICE FINAL:")
        # Eve retrieves Alice final message from public network
        alice_final_package_received_eve = public_network_eve_alice["alice_final_package"]
        print("\tAlice final message package retrieved from public network.\n")

        # Eve decodes final message from Alice
        alice_final_message_received_eve = decode_message(alice_final_package_received_eve)

        # Eve retrieves previous transcript of response message for final message verification
        print("\tEve response message retrieved from memory:")
        B_response_to_A_decoded_eve = decode_message(bob_response_package_eve)

        # Eve verifies final message from Alice with previously sent response message
        verify_received_message_package(alice_final_message_received_eve, eve_local_package_for_alice, B_response_to_A_decoded_eve)

        print("\tEVE FORGING FINAL TO BOB:\n")

        # Eve retrieved Bob response message from public network
        bob_response_package_received_eve = public_network_eve_bob["bob_response_package"]
        print("\tBob response message package retrieved from public network.\n")

        # Eve decodes response message from Bob
        bob_response_message_received_eve = decode_message(bob_response_package_received_eve)

        # Eve verifies response message from Bob
        verify_received_message_package(bob_response_message_received_eve, eve_local_package_for_bob)

        # Eve adds response values to local storage
        add_received_values(bob_response_message_received_eve, eve_local_package_for_bob)

        # Eve prepares public finish message for Bob (Eve)
        A_final_to_B_eve = session_message(eve_local_package_for_bob["protocol"], "finish",
                                       eve_local_package_for_bob["initiator"], eve_local_package_for_bob["responder"],
                                       eve_local_package_for_bob["p"], eve_local_package_for_bob["g"], eve_local_package_for_bob["A"],
                                       eve_local_package_for_bob["B"], eve_local_package_for_bob["nonce_A"],
                                       eve_local_package_for_bob["nonce_B"])

        # Eve unsigned public finish message for Bob
        alice_final_package_eve = (A_final_to_B_eve, None)

        # Eve sends final message to Bob on public network
        public_network_eve_bob["alice_final_package"] = alice_final_package_eve
        print("\tAlice final message package sent to public network.\n")
        print("OFF EVE LOCAL MACHINE\n")
        # OFF EVE LOCAL MACHINE

        # ON BOB LOCAL MACHINE
        print("ON BOB LOCAL MACHINE:\n")

        # Bob retrieves Alice final message from public network
        alice_final_package_received = public_network_eve_bob["alice_final_package"]
        print("\tAlice final message package retrieved from public network.\n")

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

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:\n")
        # Eve generates secret shared key (Alice)
        eve_local_package_for_alice["secret_shared_key"] = get_shared_secret(eve_local_package_for_alice["A"], eve_local_package_for_alice["b"],
                                                                     eve_local_package_for_alice["p"])

        # Eve generates secret shared key (Bob)
        eve_local_package_for_bob["secret_shared_key"] = get_shared_secret(eve_local_package_for_bob["B"],
                                                                             eve_local_package_for_bob["a"],
                                                                             eve_local_package_for_bob["p"])

        print("OFF EVE LOCAL MACHINE\n")
        # OFF EVE LOCAL MACHINE

        # Analysis to confirm matching of secret keys; not a part of the actual exchange; NOT OVER PUBLIC NETWORK
        if alice_local_package["secret_shared_key"] == eve_local_package_for_alice["secret_shared_key"]:
            print("Alice and Eve Shared Key:", alice_local_package["secret_shared_key"])
            print()

        else:
            print("Eve Failed to Forge Key with Alice.\n")

        if bob_local_package["secret_shared_key"] == eve_local_package_for_bob["secret_shared_key"]:
            print("Bob and Eve Shared Key:", bob_local_package["secret_shared_key"])
            print()

        else:
            print("Eve Failed to Forge Key with Bob\n")

        if alice_local_package["secret_shared_key"] == bob_local_package["secret_shared_key"]:
            print("Alice and Eve Shared Key:", alice_local_package["secret_shared_key"])
        else:
            print("Alice and Bob Failed to Establish a Shared Secret Key.")

    except Exception:
        print("Key Exchange Aborted.")

# Simulate Eve MIMA attack on authenticated DH exchange
def auth_eve_demo():
    try:
        # Public Constants Used for Arguments
        PROTOCOL = "DH-CLASSROOM-AUTH-v1"
        DH_KEY_BIT_LEN = 16
        ALICE = "Alice"
        BOB = "Bob"

        # Establishing Pre-Authenticated Signatures
        # Instantiating Local Storage for Alice and Bob
        alice_local_package, bob_local_package = create_signing_identities()

        eve_local_package_for_alice = {}
        eve_local_package_for_bob = {}

        # Alice adds public constant data
        alice_local_package["protocol"] = PROTOCOL
        alice_local_package["initiator"] = ALICE
        alice_local_package["responder"] = BOB
        alice_local_package["init"]= "None"
        alice_local_package["response"]= "None"
        alice_local_package["finish"]= "None"

        # Bob adds public constant data
        bob_local_package["protocol"] = PROTOCOL
        bob_local_package["initiator"] = ALICE
        bob_local_package["responder"] = BOB
        bob_local_package["init"]= "None"
        bob_local_package["response"]= "None"
        bob_local_package["finish"]= "None"

        # Eve adds public constant data
        eve_local_package_for_alice["protocol"] = PROTOCOL
        eve_local_package_for_alice["initiator"] = ALICE
        eve_local_package_for_alice["responder"] = BOB
        eve_local_package_for_alice["init"]= "None"
        eve_local_package_for_alice["response"]= "None"
        eve_local_package_for_alice["finish"]= "None"

        eve_local_package_for_bob["protocol"] = PROTOCOL
        eve_local_package_for_bob["initiator"] = ALICE
        eve_local_package_for_bob["responder"] = BOB
        eve_local_package_for_bob["init"]= "None"
        eve_local_package_for_bob["response"]= "None"
        eve_local_package_for_bob["finish"]= "None"

        print("Pre-Established data added to local storage packages.\n")

        # Instantiating Public Networks
        public_network_eve_alice = {}
        public_network_eve_bob = {}

        # ON ALICE LOCAL MACHINE
        print("ON ALICE LOCAL MACHINE:")
        # Generating values for init message to Bob
        p = generate_prime(DH_KEY_BIT_LEN)
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
                                      alice_local_package["responder"], alice_local_package["p"],
                                      alice_local_package["g"],
                                      alice_local_package["A"], None, alice_local_package["nonce_A"], None)

        # Alice signing init message to Bob
        alice_init_package = sign_message(A_init_to_B, alice_local_package["alice_private_auth_key"])

        # Alice sends init message publicly to Bob
        # Alice sends init message publicly to Bob (Eve)
        public_network_eve_alice["alice_init_package"] = alice_init_package
        print("\tAlice init message package sent to public network.\n")

        print("OFF ALICE LOCAL MACHINE\n")
        # OFF ALICE LOCAL MACHINE

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:")

        print("\tEVE FORGING RESPONSE FOR ALICE:\n")
        # Eve retrieves Alice init message from public network
        alice_init_package_received = public_network_eve_alice["alice_init_package"]
        print("\tAlice init message package retrieved from public network.\n")

        # Eve decodes init message from Alice
        alice_init_message_received_eve = decode_message(alice_init_package_received)

        # Eve verifies message from Alice
        verify_received_message_package(alice_init_message_received_eve, eve_local_package_for_alice)

        # Eve stores init values in local storage
        add_received_values(alice_init_message_received_eve, eve_local_package_for_alice)

        # Eve copies p and g to local package for Bob
        eve_local_package_for_bob["p"] = eve_local_package_for_alice["p"]
        eve_local_package_for_bob["g"] = eve_local_package_for_alice["g"]

        # Eve generates dh keys and nonce value
        eve_bob_private_dh_key, eve_bob_public_dh_key = generate_dh_keys(p, g)
        eve_nonce_B = generate_nonce_value()

        # Eve adds values to local storage
        eve_local_package_for_alice["b"] = eve_bob_private_dh_key
        eve_local_package_for_alice["B"] = eve_bob_public_dh_key
        eve_local_package_for_alice["nonce_B"] = eve_nonce_B

        # Eve prepares public response message to Alice
        B_response_to_A_eve = session_message(eve_local_package_for_alice["protocol"], "response",
                                              eve_local_package_for_alice["initiator"],
                                              eve_local_package_for_alice["responder"],
                                              eve_local_package_for_alice["p"], eve_local_package_for_alice["g"],
                                              eve_local_package_for_alice["A"],
                                              eve_local_package_for_alice["B"],
                                              eve_local_package_for_alice["nonce_A"],
                                              eve_local_package_for_alice["nonce_B"])

        # Eve unsigned response package.
        bob_response_package_eve = (B_response_to_A_eve, None)

        # Eve sends response message publicly to Alice
        public_network_eve_alice["bob_response_package"] = bob_response_package_eve
        print("\tEve response message package sent to public network.\n")

        print("\tFORGING INIT MESSAGE FOR BOB:")
        # Generating values for init message to Bob
        eve_alice_private_dh_key, eve_alice_public_dh_key = generate_dh_keys(p, g)
        eve_nonce_A = generate_nonce_value()

        # Adding generated values to Eve local storage
        eve_local_package_for_bob["A"] = eve_alice_public_dh_key
        eve_local_package_for_bob["a"] = eve_alice_private_dh_key
        eve_local_package_for_bob["nonce_A"] = eve_nonce_A

        # Eve preparing public init message to Bob
        A_init_to_B_eve = session_message(eve_local_package_for_bob["protocol"], "init",
                                          eve_local_package_for_bob["initiator"],
                                          eve_local_package_for_bob["responder"], eve_local_package_for_bob["p"],
                                          eve_local_package_for_bob["g"],
                                          eve_local_package_for_bob["A"], None,
                                          eve_local_package_for_bob["nonce_A"], None)

        # Eve unsigned init package
        alice_init_package_eve = (A_init_to_B_eve, None)

        # Eve sends init message publicly to Bob
        public_network_eve_bob["alice_init_package"] = alice_init_package_eve
        print("\tAlice init message package sent to public network.\n")

        print("OFF EVE LOCAL MACHINE\n")
        # OFF EVE LOCAL MACHINE

        # ON BOB LOCAL MACHINE
        print("ON BOB LOCAL MACHINE:")

        # Bob retrieves Alice init message from public network
        alice_init_package_received = public_network_eve_bob["alice_init_package"]
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
        public_network_eve_bob["bob_response_package"] = bob_response_package
        print("\tBob response message package sent to public network.\n")

        print("OFF BOB LOCAL MACHINE\n")
        # OFF BOB LOCAL MACHINE

    except Exception:
        print("Key Exchange Aborted.")

def modified_public_dh_eve_demo():

    try:
        # Public Constants Used for Arguments
        PROTOCOL = "DH-CLASSROOM-AUTH-v1"
        DH_KEY_BIT_LEN = 16
        ALICE = "Alice"
        BOB = "Bob"

        # Establishing Pre-Authenticated Signatures
        # Instantiating Local Storage for Alice and Bob
        alice_local_package, bob_local_package = create_signing_identities()

        eve_local_package = {}

        # Alice adds public constant data
        alice_local_package["protocol"] = PROTOCOL
        alice_local_package["initiator"] = ALICE
        alice_local_package["responder"] = BOB
        alice_local_package["init"]= "None"
        alice_local_package["response"]= "None"
        alice_local_package["finish"]= "None"

        # Bob adds public constant data
        bob_local_package["protocol"] = PROTOCOL
        bob_local_package["initiator"] = ALICE
        bob_local_package["responder"] = BOB
        bob_local_package["init"]= "None"
        bob_local_package["response"]= "None"
        bob_local_package["finish"]= "None"

        # Eve adds public constant data
        eve_local_package["protocol"] = PROTOCOL
        eve_local_package["initiator"] = ALICE
        eve_local_package["responder"] = BOB
        eve_local_package["init"]= "None"
        eve_local_package["response"]= "None"
        eve_local_package["finish"]= "None"

        print("Pre-Established data added to local storage packages.\n")

        # Instantiating Public Networks
        public_network = {}

        # ON ALICE LOCAL MACHINE
        print("ON ALICE LOCAL MACHINE:")
        # Generating values for init message to Bob
        p = generate_prime(DH_KEY_BIT_LEN)
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

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:")

        print("\tEVE FORGING A IN ALICE INIT MESSAGE:\n")
        # Eve retrieves Alice init message from public network
        alice_init_package_received = public_network["alice_init_package"]
        print("\tAlice init message package retrieved from public network.\n")

        # Eve decodes init message from Alice
        alice_init_message_received_eve = decode_message(alice_init_package_received)

        # Eve verifies message from Alice
        verify_received_message_package(alice_init_message_received_eve, eve_local_package)

        # Eve stores init values in local storage
        add_received_values(alice_init_message_received_eve, eve_local_package)

        # Generating values for init message to Bob
        eve_alice_private_dh_key, eve_alice_public_dh_key = generate_dh_keys(p, g)

        # Adding generated values to Eve local storage
        eve_local_package["A"] = eve_alice_public_dh_key
        eve_local_package["a"] = eve_alice_private_dh_key

        # Eve preparing public init message to Bob
        A_init_to_B_eve = session_message(eve_local_package["protocol"], "init",
                                          eve_local_package["initiator"],
                                          eve_local_package["responder"], eve_local_package["p"],
                                          eve_local_package["g"],
                                          eve_local_package["A"], None,
                                          eve_local_package["nonce_A"], None)

        alice_init_message_altered = (A_init_to_B_eve, alice_init_package[1])

        # Eve adds altered message to Alice init package
        public_network["alice_init_package"] = alice_init_message_altered
        print("\tAlice init message package A value modified.\n")

        print("OFF EVE LOCAL MACHINE\n")
        # OFF EVE LOCAL MACHINE

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

    except Exception:
        print("Key Exchange Aborted.")

def modified_prime_eve_demo():

    try:
        # Public Constants Used for Arguments
        PROTOCOL = "DH-CLASSROOM-AUTH-v1"
        DH_KEY_BIT_LEN = 16
        ALICE = "Alice"
        BOB = "Bob"
        INIT_MESSAGE = "init"
        RESPONSE_MESSAGE = "response"
        FINISH_MESSAGE = "finish"

        # Establishing Pre-Authenticated Signatures
        # Instantiating Local Storage for Alice and Bob
        alice_local_package, bob_local_package = create_signing_identities()

        eve_local_package = {}

        # Alice adds public constant data
        alice_local_package["protocol"] = PROTOCOL
        alice_local_package["initiator"] = ALICE
        alice_local_package["responder"] = BOB
        alice_local_package["init"]= "None"
        alice_local_package["response"]= "None"
        alice_local_package["finish"]= "None"

        # Bob adds public constant data
        bob_local_package["protocol"] = PROTOCOL
        bob_local_package["initiator"] = ALICE
        bob_local_package["responder"] = BOB
        bob_local_package["init"]= "None"
        bob_local_package["response"]= "None"
        bob_local_package["finish"]= "None"

        # Eve adds public constant data
        eve_local_package["protocol"] = PROTOCOL
        eve_local_package["initiator"] = ALICE
        eve_local_package["responder"] = BOB
        eve_local_package["init"]= "None"
        eve_local_package["response"]= "None"
        eve_local_package["finish"]= "None"

        print("Pre-Established data added to local storage packages.\n")

        # Instantiating Public Networks
        public_network = {}

        # ON ALICE LOCAL MACHINE
        print("ON ALICE LOCAL MACHINE:")
        # Generating values for init message to Bob
        p = generate_prime(DH_KEY_BIT_LEN)
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

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:")

        print("\tEVE FORGING NEW PRIME IN ALICE INIT MESSAGE:\n")
        # Eve retrieves Alice init message from public network
        alice_init_package_received = public_network["alice_init_package"]
        print("\tAlice init message package retrieved from public network.\n")

        # Eve decodes init message from Alice
        alice_init_message_received_eve = decode_message(alice_init_package_received)

        # Eve verifies message from Alice
        verify_received_message_package(alice_init_message_received_eve, eve_local_package)

        # Eve stores init values in local storage
        add_received_values(alice_init_message_received_eve, eve_local_package)

        # Eve generates new prime values
        p_eve = generate_prime(DH_KEY_BIT_LEN)
        p_factors_eve = prime_factors(p - 1)
        g_eve = generator_selection(p, p_factors)
        eve_private_dh_key, eve_public_dh_key = generate_dh_keys(p, g)

        # Adding generated values to Alice local storage
        eve_local_package["p"] = p
        eve_local_package["g"] = g
        eve_local_package["A"] = eve_public_dh_key
        eve_local_package["a"] = eve_private_dh_key

        # Eve preparing public init message to Bob
        A_init_to_B_eve = session_message(eve_local_package["protocol"], "init",
                                          eve_local_package["initiator"],
                                          eve_local_package["responder"], eve_local_package["p"],
                                          eve_local_package["g"],
                                          eve_local_package["A"], None,
                                          eve_local_package["nonce_A"], None)

        alice_init_message_altered = (A_init_to_B_eve, alice_init_package[1])

        # Eve adds altered message to Alice init package
        public_network["alice_init_package"] = alice_init_message_altered
        print("\tAlice init message package prime value modified.\n")

        print("OFF EVE LOCAL MACHINE\n")
        # OFF EVE LOCAL MACHINE

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

    except Exception:
        print("Key Exchange Aborted.")

def modified_identity_eve_demo():

    try:
        # Public Constants Used for Arguments
        PROTOCOL = "DH-CLASSROOM-AUTH-v1"
        DH_KEY_BIT_LEN = 16
        ALICE = "Alice"
        BOB = "Bob"

        # Establishing Pre-Authenticated Signatures
        # Instantiating Local Storage for Alice and Bob
        alice_local_package, bob_local_package = create_signing_identities()

        eve_local_package = {}

        # Alice adds public constant data
        alice_local_package["protocol"] = PROTOCOL
        alice_local_package["initiator"] = ALICE
        alice_local_package["responder"] = BOB
        alice_local_package["init"]= "None"
        alice_local_package["response"]= "None"
        alice_local_package["finish"]= "None"

        # Bob adds public constant data
        bob_local_package["protocol"] = PROTOCOL
        bob_local_package["initiator"] = ALICE
        bob_local_package["responder"] = BOB
        bob_local_package["init"]= "None"
        bob_local_package["response"]= "None"
        bob_local_package["finish"]= "None"

        # Eve adds public constant data
        eve_local_package["protocol"] = PROTOCOL
        eve_local_package["initiator"] = ALICE
        eve_local_package["responder"] = BOB
        eve_local_package["init"]= "None"
        eve_local_package["response"]= "None"
        eve_local_package["finish"]= "None"

        print("Pre-Established data added to local storage packages.\n")

        # Instantiating Public Networks
        public_network = {}

        # ON ALICE LOCAL MACHINE
        print("ON ALICE LOCAL MACHINE:")
        # Generating values for init message to Bob
        p = generate_prime(DH_KEY_BIT_LEN)
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

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:")

        print("\tEVE FORGING IDENTITY LABEL IN ALICE INIT MESSAGE:\n")
        # Eve retrieves Alice init message from public network
        alice_init_package_received = public_network["alice_init_package"]
        print("\tAlice init message package retrieved from public network.\n")

        # Eve decodes init message from Alice
        alice_init_message_received_eve = decode_message(alice_init_package_received)

        # Eve verifies message from Alice
        verify_received_message_package(alice_init_message_received_eve, eve_local_package)

        # Eve stores init values in local storage
        add_received_values(alice_init_message_received_eve, eve_local_package)

        # Adding generated values to Eve local storage
        eve_local_package["initiator"] = "Eve"

        # Eve preparing public init message to Bob
        A_init_to_B_eve = session_message(eve_local_package["protocol"], "init",
                                          eve_local_package["initiator"],
                                          eve_local_package["responder"], eve_local_package["p"],
                                          eve_local_package["g"],
                                          eve_local_package["A"], None,
                                          eve_local_package["nonce_A"], None)

        alice_init_message_altered = (A_init_to_B_eve, alice_init_package[1])

        # Eve adds altered message to Alice init package
        public_network["alice_init_package"] = alice_init_message_altered
        print("\tAlice init message package initiator identity modified.\n")

        print("OFF EVE LOCAL MACHINE\n")
        # OFF EVE LOCAL MACHINE

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

    except Exception:
        print("Key Exchange Aborted.")

# Simulate Eve MIMA attack on authenticated DH exchange
def signed_eve_demo():
    try:
        # Public Constants Used for Arguments
        PROTOCOL = "DH-CLASSROOM-AUTH-v1"
        DH_KEY_BIT_LEN = 16
        ALICE = "Alice"
        BOB = "Bob"

        # Establishing Pre-Authenticated Signatures
        # Instantiating Local Storage for Alice and Bob
        alice_local_package, bob_local_package = create_signing_identities()

        eve_local_package_for_bob, eve_local_package_for_alice = create_signing_identities()

        # Alice adds public constant data
        alice_local_package["protocol"] = PROTOCOL
        alice_local_package["initiator"] = ALICE
        alice_local_package["responder"] = BOB
        alice_local_package["init"]= "None"
        alice_local_package["response"]= "None"
        alice_local_package["finish"]= "None"

        # Bob adds public constant data
        bob_local_package["protocol"] = PROTOCOL
        bob_local_package["initiator"] = ALICE
        bob_local_package["responder"] = BOB
        bob_local_package["init"]= "None"
        bob_local_package["response"]= "None"
        bob_local_package["finish"]= "None"

        # Eve adds public constant data
        eve_local_package_for_alice["protocol"] = PROTOCOL
        eve_local_package_for_alice["initiator"] = ALICE
        eve_local_package_for_alice["responder"] = BOB
        eve_local_package_for_alice["init"]= "None"
        eve_local_package_for_alice["response"]= "None"
        eve_local_package_for_alice["finish"]= "None"

        eve_local_package_for_bob["protocol"] = PROTOCOL
        eve_local_package_for_bob["initiator"] = ALICE
        eve_local_package_for_bob["responder"] = BOB
        eve_local_package_for_bob["init"]= "None"
        eve_local_package_for_bob["response"]= "None"
        eve_local_package_for_bob["finish"]= "None"

        print("Pre-Established data added to local storage packages.\n")

        # Instantiating Public Networks
        public_network_eve_alice = {}
        public_network_eve_bob = {}

        # ON ALICE LOCAL MACHINE
        print("ON ALICE LOCAL MACHINE:")
        # Generating values for init message to Bob
        p = generate_prime(DH_KEY_BIT_LEN)
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
                                      alice_local_package["responder"], alice_local_package["p"],
                                      alice_local_package["g"],
                                      alice_local_package["A"], None, alice_local_package["nonce_A"], None)

        # Alice signing init message to Bob
        alice_init_package = sign_message(A_init_to_B, alice_local_package["alice_private_auth_key"])

        # Alice sends init message publicly to Bob
        # Alice sends init message publicly to Bob (Eve)
        public_network_eve_alice["alice_init_package"] = alice_init_package
        print("\tAlice init message package sent to public network.\n")

        print("OFF ALICE LOCAL MACHINE\n")
        # OFF ALICE LOCAL MACHINE

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:")

        print("\tEVE FORGING RESPONSE FOR ALICE:\n")
        # Eve retrieves Alice init message from public network
        alice_init_package_received = public_network_eve_alice["alice_init_package"]
        print("\tAlice init message package retrieved from public network.\n")

        # Eve decodes init message from Alice
        alice_init_message_received_eve = decode_message(alice_init_package_received)

        # Eve verifies message from Alice
        verify_received_message_package(alice_init_message_received_eve, eve_local_package_for_alice)

        # Eve stores init values in local storage
        add_received_values(alice_init_message_received_eve, eve_local_package_for_alice)

        # Eve copies p and g to local package for Bob
        eve_local_package_for_bob["p"] = eve_local_package_for_alice["p"]
        eve_local_package_for_bob["g"] = eve_local_package_for_alice["g"]

        # Eve generates dh keys and nonce value
        eve_bob_private_dh_key, eve_bob_public_dh_key = generate_dh_keys(p, g)
        eve_nonce_B = generate_nonce_value()

        # Eve adds values to local storage
        eve_local_package_for_alice["b"] = eve_bob_private_dh_key
        eve_local_package_for_alice["B"] = eve_bob_public_dh_key
        eve_local_package_for_alice["nonce_B"] = eve_nonce_B

        # Eve prepares public response message to Alice
        B_response_to_A_eve = session_message(eve_local_package_for_alice["protocol"], "response",
                                              eve_local_package_for_alice["initiator"],
                                              eve_local_package_for_alice["responder"],
                                              eve_local_package_for_alice["p"], eve_local_package_for_alice["g"],
                                              eve_local_package_for_alice["A"],
                                              eve_local_package_for_alice["B"],
                                              eve_local_package_for_alice["nonce_A"],
                                              eve_local_package_for_alice["nonce_B"])

        # Eve signed response package.
        bob_response_package_eve = sign_message(B_response_to_A_eve, eve_local_package_for_alice["bob_private_auth_key"])

        # Eve sends response message publicly to Alice
        public_network_eve_alice["bob_response_package"] = bob_response_package_eve
        print("\tEve response message package sent to public network.\n")

        print("\tFORGING INIT MESSAGE FOR BOB:")
        # Generating values for init message to Bob
        eve_alice_private_dh_key, eve_alice_public_dh_key = generate_dh_keys(p, g)
        eve_nonce_A = generate_nonce_value()

        # Adding generated values to Eve local storage
        eve_local_package_for_bob["A"] = eve_alice_public_dh_key
        eve_local_package_for_bob["a"] = eve_alice_private_dh_key
        eve_local_package_for_bob["nonce_A"] = eve_nonce_A

        # Eve preparing public init message to Bob
        A_init_to_B_eve = session_message(eve_local_package_for_bob["protocol"], "init",
                                          eve_local_package_for_bob["initiator"],
                                          eve_local_package_for_bob["responder"], eve_local_package_for_bob["p"],
                                          eve_local_package_for_bob["g"],
                                          eve_local_package_for_bob["A"], None,
                                          eve_local_package_for_bob["nonce_A"], None)

        # Eve signed init package
        alice_init_package_eve = sign_message(A_init_to_B_eve, eve_local_package_for_bob["alice_private_auth_key"])

        # Eve sends init message publicly to Bob
        public_network_eve_bob["alice_init_package"] = alice_init_package_eve
        print("\tAlice init message package sent to public network.\n")

        print("OFF EVE LOCAL MACHINE\n")
        # OFF EVE LOCAL MACHINE

        # ON BOB LOCAL MACHINE
        print("ON BOB LOCAL MACHINE:")

        # Bob retrieves Alice init message from public network
        alice_init_package_received = public_network_eve_bob["alice_init_package"]
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
        public_network_eve_bob["bob_response_package"] = bob_response_package
        print("\tBob response message package sent to public network.\n")

        print("OFF BOB LOCAL MACHINE\n")
        # OFF BOB LOCAL MACHINE

    except Exception:
        print("Key Exchange Aborted.")

def reused_response_eve_demo():
    try:
        print("START EXCHANGE 1:\n")
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
        alice_local_package["init"]= "None"
        alice_local_package["response"]= "None"
        alice_local_package["finish"]= "None"

        # Bob adds public constant data
        bob_local_package["protocol"] = PROTOCOL
        bob_local_package["initiator"] = ALICE
        bob_local_package["responder"] = BOB
        bob_local_package["init"]= "None"
        bob_local_package["response"]= "None"
        bob_local_package["finish"]= "None"

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

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:\n")

        # Eve stores Bob response message
        ripped_response = public_network["bob_response_package"]

        print("\tBob response message ripped from public network.\n")
        print("OFF EVE LOCAL MACHINE\n")
        # OFF EVE LOCAL MACHINE

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

        print("Authenticated DH Key Exchange successfully completed.\n")
        print("END EXCHANGE 1\n")

        print("START EXCHANGE 2\n")

        # Alice adds public constant data
        alice_local_package["protocol"] = PROTOCOL
        alice_local_package["initiator"] = ALICE
        alice_local_package["responder"] = BOB
        alice_local_package["init"]= "None"
        alice_local_package["response"]= "None"
        alice_local_package["finish"]= "None"

        # Bob adds public constant data
        bob_local_package["protocol"] = PROTOCOL
        bob_local_package["initiator"] = ALICE
        bob_local_package["responder"] = BOB
        bob_local_package["init"]= "None"
        bob_local_package["response"]= "None"
        bob_local_package["finish"]= "None"

        print("Pre-Established data added to local storage packages.\n")

        # Instantiating Public Network
        public_network = {}

        # ON ALICE LOCAL MACHINE
        print("ON ALICE LOCAL MACHINE:")
        # Generating values for init message to Bob
        p = generate_prime(DH_KEY_BIT_LEN)
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
                                      alice_local_package["responder"], alice_local_package["p"],
                                      alice_local_package["g"],
                                      alice_local_package["A"], None, alice_local_package["nonce_A"], None)

        # Alice signing init message to Bob
        alice_init_package = sign_message(A_init_to_B, alice_local_package["alice_private_auth_key"])

        # Alice sends init message publicly to Bob
        public_network["alice_init_package"] = alice_init_package
        print("\tAlice init message package sent to public network.\n")

        print("OFF ALICE LOCAL MACHINE\n")
        # OFF ALICE LOCAL MACHINE

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:\n")

        public_network["bob_response_package"] = ripped_response

        print("Old Bob response message package sent to public network.\n")
        print("OFF EVE LOCAL MACHINE\n")

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

    except Exception as e:
        print(f"{e}\n")
        print("Key Exchange Aborted.")

def reused_finish_eve_demo():
    try:
        print("START EXCHANGE 1:\n")
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
        alice_local_package["init"]= "None"
        alice_local_package["response"]= "None"
        alice_local_package["finish"]= "None"

        # Bob adds public constant data
        bob_local_package["protocol"] = PROTOCOL
        bob_local_package["initiator"] = ALICE
        bob_local_package["responder"] = BOB
        bob_local_package["init"]= "None"
        bob_local_package["response"]= "None"
        bob_local_package["finish"]= "None"

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

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:\n")

        # Eve stores Bob response message
        ripped_response = public_network["alice_final_package"]

        print("\tAlice final message ripped from public network.\n")
        print("OFF EVE LOCAL MACHINE\n")
        # OFF EVE LOCAL MACHINE

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

        print("Authenticated DH Key Exchange successfully completed.\n")
        print("END EXCHANGE 1\n")

        print("START EXCHANGE 2\n")

        alice_local_package.pop("B")
        alice_local_package.pop("nonce_B")
        alice_local_package.pop("secret_shared_key")

        bob_local_package.pop("A")
        bob_local_package.pop("nonce_A")
        bob_local_package.pop("secret_shared_key")

        # Alice adds public constant data
        alice_local_package["protocol"] = PROTOCOL
        alice_local_package["initiator"] = ALICE
        alice_local_package["responder"] = BOB
        alice_local_package["init"]= "None"
        alice_local_package["response"]= "None"
        alice_local_package["finish"]= "None"

        # Bob adds public constant data
        bob_local_package["protocol"] = PROTOCOL
        bob_local_package["initiator"] = ALICE
        bob_local_package["responder"] = BOB
        bob_local_package["init"]= "None"
        bob_local_package["response"]= "None"
        bob_local_package["finish"]= "None"

        print("Pre-Established data added to local storage packages.\n")

        # Instantiating Public Network
        public_network = {}

        # ON ALICE LOCAL MACHINE
        print("ON ALICE LOCAL MACHINE:")
        # Generating values for init message to Bob
        p = generate_prime(DH_KEY_BIT_LEN)
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
                                      alice_local_package["responder"], alice_local_package["p"],
                                      alice_local_package["g"],
                                      alice_local_package["A"], None, alice_local_package["nonce_A"], None)

        # Alice signing init message to Bob
        alice_init_package = sign_message(A_init_to_B, alice_local_package["alice_private_auth_key"])

        # Alice sends init message publicly to Bob
        public_network["alice_init_package"] = alice_init_package
        print("\tAlice init message package sent to public network.\n")

        print("OFF ALICE LOCAL MACHINE\n")
        # OFF ALICE LOCAL MACHINE

        ## ON BOB LOCAL MACHINE
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

        print(alice_local_package)

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

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:\n")

        public_network["alice_final_package"] = ripped_response

        print("Old Alice final message package sent to public network.\n")
        print("OFF EVE LOCAL MACHINE\n")

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

    except Exception as e:
        print(f"{e}\n")
        print("Key Exchange Aborted.")

def duplicate_finish_eve_demo():
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
        alice_local_package["init"]= "None"
        alice_local_package["response"]= "None"
        alice_local_package["finish"]= "None"

        # Bob adds public constant data
        bob_local_package["protocol"] = PROTOCOL
        bob_local_package["initiator"] = ALICE
        bob_local_package["responder"] = BOB
        bob_local_package["init"]= "None"
        bob_local_package["response"]= "None"
        bob_local_package["finish"]= "None"

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

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:\n")

        # Eve stores Bob response message
        ripped_response = public_network["alice_final_package"]

        print("\tAlice final message ripped from public network.\n")
        print("OFF EVE LOCAL MACHINE\n")
        # OFF EVE LOCAL MACHINE

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

        # ON EVE LOCAL MACHINE
        print("ON EVE LOCAL MACHINE:\n")

        # Eve stores Bob response message
        public_network["alice_final_package"] = ripped_response

        print("\tAlice final message duplicate uploaded to public network.\n")
        print("OFF EVE LOCAL MACHINE\n")
        # OFF EVE LOCAL MACHINE

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

        print("Authenticated DH Key Exchange successfully completed.\n")

    except Exception as e:
        print(f"{e}\n")
        print("Key Exchange Aborted.")
        
def eve_demo_call():
    call = input("Enter Demo Function to Run (See README.txt for Options): ")

    while call != "quit":
        if call == "unauth":
            unauth_eve_demo()

        elif call == "auth":
            auth_eve_demo()

        elif call == "A":
            modified_public_dh_eve_demo()

        elif call == "prime":
            modified_prime_eve_demo()

        elif call == "id":
            modified_identity_eve_demo()

        elif call == "signed":
            signed_eve_demo()

        elif call == "response":
            reused_response_eve_demo()

        elif call == "refinish":
            reused_finish_eve_demo()

        elif call == "dupfinish":
            duplicate_finish_eve_demo()

        call = input("Enter Demo Function to Run (See README.txt for Options) (Type 'quit' to End): ")

eve_demo_call()