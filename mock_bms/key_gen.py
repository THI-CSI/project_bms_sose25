from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import pathlib

def bms_signing_key_pair_generation():
    bms_private_signing_key = ec.generate_private_key(ec.SECP256R1())
    bms_private_signing_key_der = bms_private_signing_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  
    )
    keys_dir = pathlib.Path(__file__).parent / "keys"
    keys_dir.mkdir(exist_ok=True)
    key_path = (keys_dir / "bms_private_signing_key.der")
    if not key_path.is_file(): 
        with open(key_path, "wb") as f:
            f.write(bms_private_signing_key_der)
        key_path.chmod(0o600)

def writing_did(bms_did):
    did_path = (pathlib.Path(__file__).parent / "bms_did")
    if not did_path.is_file(): 
        with open(did_path, "w", encoding="utf-8") as f:
            f.write(bms_did)