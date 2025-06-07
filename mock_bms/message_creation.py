from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import json
from datetime import timezone, datetime
import os
import pathlib

def read_key(filename: str):
    keys_dir = pathlib.Path(__file__).parent / "keys"
    key_path = keys_dir / filename
    if key_path.is_file():
        with open(key_path, "rb") as f:
            bms_private_signing_key_der = f.read()
            private_key = serialization.load_der_private_key(
                bms_private_signing_key_der,
                password=None,
            )
            return private_key
    else:
        raise FileNotFoundError("Privater Schlüssel nicht gefunden.")

def read_bms_did():
    did_path = pathlib.Path(__file__).parent / "bms_did"
    if did_path.is_file():
        with open(did_path, "r", encoding="utf-8") as f:
            bms_did = f.read().strip()
            return bms_did
    else:
        raise FileNotFoundError("DID-Datei nicht gefunden.")

def message_creation(dynamic_battery_data: bytes, cloud_public_key_der_base64: str):
    bms_did = read_bms_did().encode('utf-8')
    bms_private_signing_key = read_key("bms_private_signing_key.der")
    
    cloud_public_key_der = base64.b64decode(cloud_public_key_der_base64)
    cloud_public_key = serialization.load_der_public_key(cloud_public_key_der)

    # Generate ECC ephemeral key pair and export public key
    private_ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    public_ephemeral_key = private_ephemeral_key.public_key()
    ephemeral_public_key_der = public_ephemeral_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Key aggreement with ECDH
    shared_secret = private_ephemeral_key.exchange(ec.ECDH(), cloud_public_key)

    # Key derivation with HKDF(SHA-256)
    info = ephemeral_public_key_der + cloud_public_key_der
    salt = os.urandom(32)
    aes_derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    ).derive(shared_secret)

    # AES-GCM 256
    nonce = os.urandom(12)
    associated_data = nonce
    aesgcm = AESGCM(aes_derived_key)
    ciphertext = aesgcm.encrypt(nonce, dynamic_battery_data, associated_data)

    # Get timestamp
    timestamp_bytes = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ").encode("utf-8")

    # Create message
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    associated_data_b64 = base64.b64encode(associated_data).decode('utf-8')
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    ephemeral_public_key_b64 = base64.b64encode(ephemeral_public_key_der).decode('utf-8')
    did_b64 = base64.b64encode(bms_did).decode('utf-8')
    timestamp_b64 = base64.b64encode(timestamp_bytes).decode("utf-8")
    message = {
        "ciphertext": ciphertext_b64,
        "aad": associated_data_b64,
        "salt": salt_b64,
        "ephemeral_public_key": ephemeral_public_key_b64,
        "did": did_b64,
        "timestamp": timestamp_b64
    }
    message_json = json.dumps(message)
    message_bytes = message_json.encode("utf-8")

    # Sign messsage with ECDSA and add to message
    signature_der = bms_private_signing_key.sign(
        message_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    r, s = utils.decode_dss_signature(signature_der)
    signature_raw = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    signature_b64 = base64.b64encode(signature_raw).decode('utf-8')
    message["signature"] = signature_b64
    signed_json_message = json.dumps(message)
    signed_json_message_bytes = signed_json_message.encode("utf-8")

    return signed_json_message_bytes