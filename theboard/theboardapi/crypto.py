import string
import base64

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import random, get_random_bytes
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS

from .models import TheBoardMember
from .exceptions.InvalidSignature import InvalidSignature


def generate_passphrase(length=20):
    chars = string.ascii_letters + string.digits + ".,!^*"
    return ''.join(random.choice(chars) for _ in range(length))


def generate_signing_key(passphrase):
    """ Generates the ECDSA private key for signing """
    key = ECC.generate(curve='P-256')
    return key.export_key(format='PEM', passphrase=passphrase,
                          protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                          prot_params={'iteration_count': 131702})


def generate_encryption_key(passphrase):
    """ Generates the RSA private key for encryption """
    key = RSA.generate(2048)
    return key.export_key(pkcs=8, passphrase=passphrase, format='PEM',
                          protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                          prot_params={'iteration_count': 131702}).decode('utf-8')


def generate_member(screen_name):
    """ Generates the cryptographic components needed to access the board enclave """
    member = TheBoardMember()
    member.screen_name = screen_name

    passphrase = generate_passphrase()
    ciphertext, nonce = encrypt_message(passphrase)
    member.passphrase = f"{{'ciphertext':'{ciphertext}', 'nonce':'{nonce}'}}"

    signing_key = generate_signing_key(passphrase)
    member.signing_key = signing_key

    encryption_key = generate_encryption_key(passphrase)
    member.encryption_key = encryption_key
    return member, passphrase

def get_ecc_public_key(pem, passphrase):
    """ Returns the ECC public key derived from the ECDSA private key"""
    pem_bytes = pem.encode('UTF-8')
    private_key = ECC.import_key(pem_bytes, passphrase=passphrase)
    public_key = private_key.public_key()
    pkpem = public_key.export_key(format='PEM')
#    print(f'EC public key PEM: {pkpem}')
    return pkpem


def get_rsa_public_key(pem, passphrase):
    """ Returns the RSA public key derived from the RSA private key"""
    pem_bytes = pem.encode('UTF-8')
    private_key = RSA.import_key(pem_bytes, passphrase=passphrase)
    public_key = private_key.public_key()
    pkpem = public_key.export_key(format='PEM')
#    print(f'RSA public key PEM: {pkpem}')
    return pkpem.decode('UTF-8')


def validate_signature(public_key_pem, fields, signature):
    """
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
    """
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
    private_key_bytes = private_key_pem.encode('utf-8')
    private_key = ECC.import_key(private_key_bytes, passphrase=passphrase)
    h = SHA256.new()
    for field in fields:
        h.update(field)
    signer = DSS.new(private_key, 'fips-186-3')
    signed = signer.sign(h)
    return base64.b64encode(signed)


def encrypt_message(message):
    """
    Encrypt a message using AES 256 GCM
    :param message: The message to encrypt
    :type message: str
    :return The encrypted message and the cipher IV (nonce), both base64 encoded
    :rtype: (str, str)
    """
    with open('/opt/the-board/keys/api/aes_key', 'r') as f:
        lines = f.readlines()
    key = base64.b64decode(lines[0])
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(nonce).decode('utf-8')


def decrypt_message(ciphertext, nonce):
    """
    Decrypt a message using AES 256 GCM
    :param ciphertext: The ciphertext to decrypt, base64 encoded
    :type ciphertext: str
    :param nonce: The cipher IV (nonce), base64 encoded
    :type nonce: str
    :return The decrypted message
    :rtype: str
    """
    with open('/opt/the-board/keys/api/aes_key', 'r') as f:
        lines = f.readlines()
    key = base64.b64decode(lines[0])
    ciphertext_bytes = base64.b64decode(ciphertext)
    nonce_bytes = base64.b64decode(nonce)
    cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(nonce_bytes))
    return cipher.decrypt(ciphertext_bytes).decode('utf-8')
