import base64

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS

from .crypto2 import generate_passphrase, encrypt_message, generate_signing_key
from .exceptions.InvalidSignature import InvalidSignature
from .models import TheBoardMember

"""
def get_ecc_public_key(pem, passphrase):
    
    pem_bytes = pem.encode('UTF-8')
    private_key = ECC.import_key(pem_bytes, passphrase=passphrase)
    public_key = private_key.public_key()
    pkpem = public_key.export_key(format='PEM')
#    print(f'EC public key PEM: {pkpem}')
    return pkpem


def get_rsa_public_key(pem, passphrase):
    
    pem_bytes = pem.encode('UTF-8')
    private_key = RSA.import_key(pem_bytes, passphrase=passphrase)
    public_key = private_key.public_key()
    pkpem = public_key.export_key(format='PEM')
#    print(f'RSA public key PEM: {pkpem}')
    return pkpem.decode('UTF-8')
"""

"""
def validate_signature(public_key_pem, fields, signature):
    Validates the signature against the given fields
    :param public_key_pem: PEM encoded ECC signature public key
    :type public_key_pem: str
    :param fields: List of fields to hash
    :type fields: list
    :param signature: Base64 encoded signature to validate
    :type signature: str
    :return None
    :rtype None
    :raises InvalidSignature: If the signature is invalid
    public_key_bytes = public_key_pem.encode('utf-8')
    public_key = ECC.import_key(public_key_pem)
    h = SHA256.new()
    for field in fields:
        h.update(field.encode('utf-8'))
    print(f'Hash bytes: {h.hexdigest()}')
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        signature_bytes = base64.b64decode(signature)
        print(f'Signature bytes: {signature_bytes.hex()}')
        verifier.verify(h, signature_bytes)
    except ValueError as e:
        print(f'Value error: {e}')
        raise InvalidSignature()
    """

"""
def sign_message(private_key_pem, passphrase, fields):
    Signs the given fields using the given private_key_pem and passphrase
    :param private_key_pem: PEM encoded ECC private key
    :type private_key_pem: str
    :param passphrase: The passphrase for the private key
    :type passphrase: str
    :param fields: List of fields to sign
    :type fields: list
    :return The base 64 encoded signature
    :rtype: str
    private_key_bytes = private_key_pem.encode('utf-8')
    private_key = ECC.import_key(private_key_bytes, passphrase=passphrase)
    h = SHA256.new()
    for field in fields:
        h.update(field)
    signer = DSS.new(private_key, 'fips-186-3')
    signed = signer.sign(h)
    return base64.b64encode(signed)
    """

"""
def encrypt_message(message):
    Encrypt a message using AES 256 GCM
    :param message: The message to encrypt
    :type message: str
    :return The encrypted message and the cipher IV (nonce), both base64 encoded
    :rtype: (str, str)
    with open('/opt/the-board/keys/api/aes_key', 'r') as f:
        lines = f.readlines()
    key = base64.b64decode(lines[0])
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(nonce).decode('utf-8')


def decrypt_message(ciphertext, nonce):
    Decrypt a message using AES 256 GCM
    :param ciphertext: The ciphertext to decrypt, base64 encoded
    :type ciphertext: str
    :param nonce: The cipher IV (nonce), base64 encoded
    :type nonce: str
    :return The decrypted message
    :rtype: str
    with open('/opt/the-board/keys/api/aes_key', 'r') as f:
        lines = f.readlines()
    key = base64.b64decode(lines[0])
    ciphertext_bytes = base64.b64decode(ciphertext)
    nonce_bytes = base64.b64decode(nonce)
    cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(nonce_bytes))
    return cipher.decrypt(ciphertext_bytes).decode('utf-8')
"""
