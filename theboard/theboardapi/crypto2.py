import base64
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

from theboardapi.exceptions.InvalidSignature import InvalidSignature

def generate_ephemeral_key():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())

def validate_signature(server_signing_key_pem, fields, signature):
    """ Validate the message signature """
    signing_public_key = serialization.load_pem_public_key(
        server_signing_key_pem.encode('UTF-8'),
        backend=default_backend()
    )

    digest = hashlib.sha256()
    for field in fields:
        digest.update(field.encode('utf-8'))
    hash_bytes = digest.digest()

    signature_bytes = base64.b64decode(signature)

    # Verify the signature
    try:
        signing_public_key.verify(signature_bytes, hash_bytes, ec.ECDSA(hashes.SHA256()))
    except Exception as e:
        print(f'Signature verification failed: {e}')
        raise InvalidSignature

def get_ecdh_shared_key(api_private_key, board_public_key):
    """ Get ECDH shared secret. Shared key is sha256 hash of shared secret """
    shared = api_private_key.exchange(ec.ECDH(), board_public_key)
    return hashlib.sha256(shared.encode('utf-8')).digest()

def encrypt_message(cleartext, secret):
    """ Encrypt cleartext message using AES-GCM. Attach IV to start of message
    :param cleartext: cleartext message
    :param secret: secret key
    :return: encrypted cleartext message base64 encoded
    """
    aesgcm = AESGCM(secret)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(cleartext, nonce)
    encrypted = nonce + ciphertext
    return base64.b64encode(encrypted).decode('UTF-8')

def decrypt_message(ciphertext, secret):
    """ Decrypt bae64 encoded text """
    bytes = base64.b64decode(ciphertext)
    nonce = bytes[0:12]
    ciphertext_bytes = bytes[12:]
    aesgcm = AESGCM(secret)
    return aesgcm.decrypt(ciphertext_bytes, nonce)
