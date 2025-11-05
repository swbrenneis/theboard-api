import string

from models import TheBoardMember
from Crypto.Random import random
from Crypto.PublicKey import ECC, RSA


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