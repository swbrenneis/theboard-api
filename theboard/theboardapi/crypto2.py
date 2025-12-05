import base64
import hashlib
import random
import string
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from theboardapi.exceptions.InvalidSignature import InvalidSignature
from theboardapi.models import TheBoardMember


def generate_ephemeral_key():
    """
    Generate the ephemeral key used to generate the ECDH shared secret
    :return The ephemeral key, PM encoded private key, PEM encoded public key
    :rtype: EllipticCurvePrivateKey, str, str
    """
    ec_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    private_key_pem = ec_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('UTF-8')
    ec_public_key = ec_private_key.public_key()
    public_key_pem = ec_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('UTF-8')
    return ec_private_key, private_key_pem, public_key_pem

def generate_signing_key(passphrase):
    """
    Generate the EC signing private key with a passphrase
    :param passphrase: The passphrase for the private key
    :type passphrase: str
    :return The EC signing key
    :rtype: str
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('UTF-8')),
    )
    return pem.decode('UTF-8')

def generate_encryption_key(passphrase):
    """
    Generate the RSA encryption private key with a passphrase
    :param passphrase: The passphrase for the private key
    :type passphrase: str
    :return The RSA encryption key
    :rtype: str
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('UTF-8')),
    )
    return pem.decode('UTF-8')

def get_public_key(pem, passphrase):
    """
    Recovers RSA or ECDSA public key form PEM-encoded private key.
    The library detects the key type
    :param pem: PEM-encoded private key
    :type pem: str
    :param passphrase: The passphrase for the private key
    :type passphrase: str
    """
    private_key = serialization.load_pem_private_key(
        pem.encode('utf-8'),
        password=passphrase.encode('UTF-8'),
    )
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('UTF-8')

def generate_member(screen_name):
    """ Generates the cryptographic components needed to access the board enclave """
    member = TheBoardMember()
    member.screen_name = screen_name

    passphrase = generate_passphrase()
    digest = hashlib.sha256()
    digest.update(passphrase.encode('utf-8'))
    hashed_passphrase = digest.digest()
    member.passphrase = base64.b64encode(hashed_passphrase).decode('UTF-8')

    signing_key = generate_signing_key(passphrase)
    member.signing_key = signing_key

    encryption_key = generate_encryption_key(passphrase)
    member.encryption_key = encryption_key
    return member, passphrase


def sign_message(private_key_pem, passphrase, fields):
    """
    Signs the given fields using the given private_key_pem and passphrase
    :param private_key_pem: PEM encoded ECC private key
    :type private_key_pem: str
    :param passphrase: The passphrase for the private key
    :type passphrase: str
    :param fields: List of fields to sign
    :type fields: list
    :return The base 64 encoded signature
    :rtype: str
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=passphrase.encode('UTF-8'),
    )
    digest = hashlib.sha256()
    for field in fields:
        digest.update(field.encode('utf-8'))
    hash_bytes = digest.digest()
    signature = private_key.sign(hash_bytes, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode('UTF-8')


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
    """
    Get ECDH shared secret. Shared key is sha256 hash of shared secret
    """
    shared = api_private_key.exchange(ec.ECDH(), board_public_key)
    print(f'Key agreement bytes: {shared.hex()}')
    return hashlib.sha256(shared).digest()


def encrypt_message(cleartext, secret=None):
    """ Encrypt cleartext message using AES-GCM. Attach IV to start of message
    :param cleartext: cleartext message
    :type cleartext: str
    :param secret: optional secret key
    :type secret: bytes
    :return: encrypted cleartext message base64 encoded
    :rtype: str
    """
    if not secret:
        # Read the key from the board master key file
        with open('/opt/the-board/keys/api/aes_key', 'r') as f:
            lines = f.readlines()
        secret = base64.b64decode(lines[0])

    iv = os.urandom(12)
    encryptor = Cipher(
        algorithm=algorithms.AES(secret),
        mode=modes.GCM(iv),
    ).encryptor()
    ciphertext = encryptor.update(cleartext.encode('UTF-8')) + encryptor.finalize()
    tag = encryptor.tag
    print(f'Secret: {secret.hex()}')
    print(f'IV: {iv.hex()}')
    print(f'Ciphertext: {ciphertext.hex()}')
    print(f'Tag: {tag.hex()}')
    encrypted = iv + ciphertext + tag
    return base64.b64encode(encrypted).decode('UTF-8')


def decrypt_message(ciphertext, secret=None):
    """
    Decrypt base64 encoded text
    :param ciphertext: base64 encoded text
    :type ciphertext: str
    :param secret: optional secret key
    :type secret: bytes
    :return: decrypted cleartext message
    :rtype: bytes
    """
    if not secret:
        # Read the key from the board master key file
        with open('/opt/the-board/keys/api/aes_key', 'r') as f:
            lines = f.readlines()
        secret = base64.b64decode(lines[0])

    decoded_bytes = base64.b64decode(ciphertext)
    nonce = decoded_bytes[0:12]
    ciphertext_bytes = decoded_bytes[12:]
    aesgcm = AESGCM(secret)
    return aesgcm.decrypt(nonce, ciphertext_bytes, associated_data=bytearray())


def import_public_key(public_key_pem):
    """
    Import public key from PEM format string
    :param public_key_pem: PEM format string
    :type public_key_pem: str
    :return: imported public key
    :rtype: EllipticCurvePublicKey
    """
    # print(f'Public key PEM: {public_key_pem}')
    public_key = serialization.load_pem_public_key(public_key_pem.encode('UTF-8'), backend=default_backend())
    return public_key


def generate_passphrase(length=20):
    chars = string.ascii_letters + string.digits + ".,!^*"
    return ''.join(random.choice(chars) for _ in range(length))
