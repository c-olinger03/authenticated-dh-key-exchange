import secrets
import json
from logging import exception

from parameters import *
from participant import *

# Generates new 32 byte nonce value, returned in hexadecimal format.
def generate_nonce_value():
    print("\tGenerating Nonce Value...")
    nonce = secrets.token_bytes(32).hex()
    print("\tNonce Value:", nonce)
    print()
    return nonce

# Used to generate a transfer message containing dictionary keys and values formatted in bytes for public transfer.
def session_message(protocol=None, message_type=None, initiator=None, responder=None,
                    p=None, g=None, A=None, B=None, nonce_A=None, nonce_B=None):
    print("\tGenerating Message...")
    print("\tMessage Type:", message_type)

    try:

        # Structure for checking args & constructing init messages
        if message_type == "init":
            if protocol is None or initiator is None or responder is None or p is None \
                    or g is None or A is None or nonce_A is None:
                raise ValueError("\tError: Missing argument for designated message type.")

            else:
                message = {"protocol": protocol, "message_type": message_type, "initiator": initiator,
                       "responder": responder, "p": p, "g": g, "A": A, "nonce_A": nonce_A}

        # Structure for checking args & constructing response & finish messages
        elif message_type == "response" or message_type == "finish":
            if protocol is None or initiator is None or responder is None or p is None \
                    or g is None or A is None or B is None or nonce_A is None or nonce_B is None:
                raise ValueError("\tError: Missing argument for designated message type.")

            else:
                message = {"protocol": protocol, "message_type": message_type, "initiator": initiator,
                       "responder": responder, "p": p, "g": g, "A": A, "B": B, "nonce_A": nonce_A, "nonce_B": nonce_B}

        # Raise error if message type not included.
        else:
            raise ValueError("\tError: Missing message type.")

        # Converts message to bytes and encodes message in utf-8
        encoded_message = json.dumps(message, sort_keys=True, separators=(",",":")).encode("utf-8")

        # Checks message for excess size
        if len(encoded_message) > 4096:
            raise ValueError("\tError: Message Exceeds 4096 bytes.")

        print("\tMessage Length (bytes):", len(encoded_message))
        print("\tMessage:", encoded_message)
        print()
        return encoded_message

    # Reject Value, Abort Exchange
    except ValueError as e:
        print(e)
        raise Exception("Aborted at Message Creation.")

# Verifies length, format, type, and attributes of message received
def verify_received_message_package(message, local_storage, previous_transcript=None):
    print("\tVerifying Received Message...")

    try:
        # Verify message size
        if len(message) > 4096:
            raise ValueError("\tError: Message Exceeds 4096 bytes.")
        print("\tMessage Length: Verified")

        # Verifying message type and format
        if "message_type" in message:

            print("\tMessage Type:", message["message_type"])

            # Verify init message format
            if message["message_type"] == "init":
                if "protocol" not in message or "initiator" not in message or "responder" not in message or \
                        "p" not in message or "g" not in message or "A" not in message or "nonce_A" not in message:
                    raise ValueError("\tError: Missing argument for designated message type.")

                if local_storage["init"] != "None":
                    raise ValueError("\tError: Duplicate Message Type Received.")

                else:
                    local_storage["init"] = "received"

            elif message["message_type"] == "response" or message["message_type"] == "finish":
                if "protocol" not in message or "initiator" not in message or "responder" not in message or \
                        "p" not in message or "g" not in message or "A" not in message or "nonce_A" not in message \
                        or "B" not in message or "nonce_B" not in message:
                    raise ValueError("\tError: Missing argument for designated message type.")

                if message["message_type"] == "response" and local_storage["response"] != "None":
                    raise ValueError("\tError: Duplicate Message Type Received.")

                else:
                    local_storage["response"] = "received"

                if message["message_type"] == "finish" and local_storage["finish"] != "None":
                    raise ValueError("\tError: Duplicate Message Type Received.")

                else:
                    local_storage["finish"] = "received"

            print("\tMessage Format: Verified")

        else:
            raise ValueError("\tError: Unknown message type.")

        # Verify protocol
        if message["protocol"] != local_storage["protocol"]:
            raise ValueError("\tError: Protocol Mismatch.")

        print("\tProtocol: Verified")

        # Verify Identities
        if message["initiator"] != local_storage["initiator"]:
            raise ValueError("\tError: Initiator Identity Mismatch.")

        print("\tInitiator: Verified")

        if message["responder"] != local_storage["responder"]:
            raise ValueError("\tError: Responder Identity Mismatch.")

        print("\tResponder: Verified")

        # Verify values of init message
        if message["message_type"] == "init":
            received_modulus_validation(message["p"])
            received_generator_validation(message["g"], message["p"])
            verify_range_peer_public_dh_key(message["A"], message["p"])

        # Verify received values match local values
        elif message["message_type"] == "response":
            for key in message:
                if key in local_storage:
                    if local_storage[key] != message[key]:
                        raise ValueError("\tError: Known Value Mismatch.")

            # Verify received B value
            verify_range_peer_public_dh_key(message["B"], local_storage["p"])

        # Verify received values match local values
        elif message["message_type"] == "finish":
            for key in message:
                if key != "message_type":
                    if message[key] != previous_transcript[key]:
                        raise ValueError("\tError: Known Value Mismatch.")

        print("\tReceived Message: Verified\n")

    # Invalid Message received, Abort Exchange
    except (TypeError, ValueError) as e:
        print(e)
        raise Exception("\tAborted at Message Validation.")

# Adds values from received message to local storage if not present
def add_received_values(message, local_storage):
    print("\tAdding Received Values...")

    try:

        # Adding init values to local storage
        if message["message_type"] == "init":
            local_storage["p"] = message["p"]
            local_storage["g"] = message["g"]
            local_storage["A"] = message["A"]
            local_storage["nonce_A"] = message["nonce_A"]

        elif message["message_type"] == "response":
            local_storage["B"] = message["B"]
            local_storage["nonce_B"] = message["nonce_B"]

        print("\tReceived values added to local storage.\n")

    except ValueError as e:
        print(e)
        raise Exception("\tAborted at Message Validation.")

# Decode message from bytes to ASCII
def decode_message(message_package):
    print("\tDecoding Message...")

    try:

        # Check valid message package
        if type(message_package) != tuple:
            raise TypeError("\tError: Message Type Mismatch, Expected tuple.")

        else:

            # Pull message from message package, convert from bytes to ASCII
            decoded_message = json.loads(message_package[0].decode("utf-8"))
            print("\tMessage Decoded:", decoded_message)
            print()
            return decoded_message

    except TypeError as e:
        print(e)
        raise Exception("\tAborted at Message Decoding.")



