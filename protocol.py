import secrets
import json

def generate_nonce_value():
    nonce = secrets.token_bytes(32)
    return nonce

def create_message():



    message = {}
    encoded_message = json.dumps(message, sort_keys=True, separators=(",",":")).encode("utf-8")

