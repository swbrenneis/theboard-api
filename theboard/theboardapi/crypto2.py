import base64
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

from theboardapi.exceptions.InvalidSignature import InvalidSignature


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