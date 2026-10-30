import secrets
import json
from parameters import *
from participant import *

def generate_nonce_value():
    nonce = secrets.token_bytes(32).hex()
    return nonce

def session_message(protocol=None, message_type=None, initiator=None, responder=None,
                    p=None, g=None, A=None, B=None, nonce_A=None, nonce_B=None):

    if message_type == "init":

        if protocol is None or initiator is None or responder is None or p is None \
                or g is None or A is None or nonce_A is None:
            raise ValueError

        else:
            message = {"protocol": protocol, "message_type": message_type, "initiator": initiator,
                   "responder": responder, "p": p, "g": g, "A": A, "nonce_A": nonce_A}

    elif message_type == "response" or message_type == "finish":

        if protocol is None or initiator is None or responder is None or p is None \
                or g is None or A is None or B is None or nonce_A is None or nonce_B is None:
            raise ValueError

        else:
            message = {"protocol": protocol, "message_type": message_type, "initiator": initiator,
                   "responder": responder, "p": p, "g": g, "A": A, "B": B, "nonce_A": nonce_A, "nonce_B": nonce_B}

    else:
        raise ValueError

    encoded_message = json.dumps(message, sort_keys=True, separators=(",",":")).encode("utf-8")

    if len(encoded_message) > 4096:
        raise ValueError

    return encoded_message

def verify_received_message_package(message, local_storage, previous_transcript=None):

    # Verify message size
    if len(message) > 4096:
        raise ValueError

    # Verifying message type and format
    if "message_type" in message:

        if message["message_type"] == "init":
            if "protocol" not in message or "initiator" not in message or "responder" not in message or \
                    "p" not in message or "g" not in message or "A" not in message or "nonce_A" not in message:
                raise ValueError

        elif message["message_type"] == "response":
            if "protocol" not in message or "initiator" not in message or "responder" not in message or \
                    "p" not in message or "g" not in message or "A" not in message or "nonce_A" not in message \
                    or "B" not in message or "nonce_B" not in message:
                raise ValueError

        elif message["message_type"] == "finish":
            if "protocol" not in message or "initiator" not in message or "responder" not in message or \
                    "p" not in message or "g" not in message or "A" not in message or "nonce_A" not in message \
                    or "B" not in message or "nonce_B" not in message:
                raise ValueError

    else:
        raise ValueError

    # Verify protocol
    if message["protocol"] != local_storage["protocol"]:
        raise ValueError

    # Verify Identities
    if message["initiator"] != local_storage["initiator"]:
        raise ValueError
    if message["responder"] != local_storage["responder"]:
        raise ValueError

    # Verify values of init message
    if message["message_type"] == "init":

        # make sure raise error if invalid *****************
        received_modulus_validation(message["p"])
        received_generator_validation(message["g"], message["p"])
        verify_range_peer_public_dh_key(message["A"], message["p"])

    # Verify received values match local values
    elif message["message_type"] == "response":
        for key in message:
            if key in local_storage:
                if local_storage[key] != message[key]:
                    raise ValueError

        # Verify received B value
        verify_range_peer_public_dh_key(message["B"], local_storage["p"])

    # Verify received values match local values
    elif message["message_type"] == "finish":
        for key in message:
            if key != "message_type":
                if message[key] != previous_transcript[key]:
                    raise ValueError


def add_received_values(message, local_storage):

    # Adding init values to local storage
    if message["message_type"] == "init":
        local_storage["p"] = message["p"]
        local_storage["g"] = message["g"]
        local_storage["A"] = message["A"]
        local_storage["nonce_A"] = message["nonce_A"]

    if message["message_type"] == "response":
        local_storage["B"] = message["B"]
        local_storage["nonce_B"] = message["nonce_B"]

def decode_message(message_package):
    try:

        if type(message_package) != tuple:
            raise TypeError

        else:
            decoded_message = json.loads(message_package[0].decode("utf-8"))

    except TypeError:
        return None

    return decoded_message

