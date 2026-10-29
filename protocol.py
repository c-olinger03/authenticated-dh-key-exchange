import secrets
import json

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

