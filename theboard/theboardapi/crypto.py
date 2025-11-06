import string
import base64

from Crypto.Hash import SHA256
from Crypto.Random import random
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS

from models import TheBoardMember
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
    return key.export_key(pkcs=8, passphrase=passphrase,
                          protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                          prot_params={'iteration_count': 131702})


def generate_member(screen_name):
    """ Generates the cryptographic components needed to access the board enclave """
    member = TheBoardMember()
    member.screen_name = screen_name

    # TODO encrypt password
    passphrase = generate_passphrase()
    member.passphrase = passphrase

    signing_key = generate_signing_key(passphrase)
    member.signing_key = signing_key.decode('utf-8')

    encryption_key = generate_encryption_key(passphrase)
    member.encryption_key = encryption_key.decode('utf-8')

    return member

def get_ecc_publicKey(pem, passphrase):
    """ Returns the ECC public key derived from the ECDSA private key"""
    pem_bytes = pem.encode('UTF-8')
    private_key = ECC.import_key(pem_bytes, passphrase=passphrase)
    public_key = private_key.public_key()
    return public_key.export_key(format='PEM')


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
    public_key = ECC.import_key(public_key_bytes)
    signature_bytes = base64.b64decode(signature)
    h = SHA256.new()
    for field in fields:
        h.update(field)
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(h, signature_bytes)
    except ValueError:
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