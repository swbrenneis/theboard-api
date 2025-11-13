import json

import requests

from .crypto import generate_member, get_ecc_public_key, sign_message, decrypt_message, \
    get_rsa_public_key
from .crypto2 import validate_signature
from .exceptions.ScreenNameInUse import ScreenNameInUse
from .exceptions.MemberNotFound import MemberNotFound
from .exceptions.InvalidPassword import InvalidPassword
from .exceptions.SessionIdMismatch import SessionIdMismatch
from .models import TheBoardMember


class TheBoardBackend:
    """ Encapsulates the back end API methods for accessing the board enclave """

    back_end_host = 'http://ec2-54-156-226-233.compute-1.amazonaws.com:8446/enclave'

    def register(self, screen_name):
        """
        Registers the given screen_name with the enclave. Stores the resulting
        member object in the database.
        :param screen_name: The screen_name to register.
        :type screen_name: str
        :return: The generated password
        :rtype: str
        :raises InvalidSignature: If the signature is invalid
        :raises ScreenNameInUse: If the screen_name is already registered
        :raises Exception: If there is a problem registering the screen_name
        """
        member, passphrase = generate_member(screen_name)
        signing_public_key_pem = get_ecc_public_key(member.signing_key, passphrase)
        encryption_public_key_pem = get_rsa_public_key(member.encryption_key, passphrase)

        url = f'{self.back_end_host}/register'
        initiate_registration = {
            "screenName": f"{screen_name}",
            'signingPublicKey': f"{signing_public_key_pem}",
            'encryptionPublicKey': f"{encryption_public_key_pem}",
        }
        # Send post request
        response = requests.post(url, json=initiate_registration)
        # Check for HTTP errors
        response.raise_for_status()
        # Decode response
        registered = response.json()
        # Validate the message signature, will raise InvalidSignature on failure
        print(registered)
        if registered['success']:
            server_signing_key_pem = registered['signingPublicKey']
            fields = [
                registered["publicId"],
                registered['enclaveKey'],
                registered['signingPublicKey'],
                registered['status']
            ]
            validate_signature(server_signing_key_pem, fields, registered['signature'])
            member.public_id = registered['publicId']
            member.enclave_key = registered['enclaveKey']
            member.server_signing_key = server_signing_key_pem
            member.save()
            return passphrase
        else:
            if registered['status'] == "Screen name exists":
                raise ScreenNameInUse("Screen name in use")
            else:
                raise Exception(registered['status'])

    def login(self, screen_name, password):
        """
        Log in using the given screen_name and password.
        :param screen_name: The screen_name to login.
        :type screen_name: str
        :param password: The password to use for logging in
        :type password: str
        :return: The authentication status and session ID and session key if successful
        :rtype: dict
        :raises MemberNotFound: If the member object cannot be found using the screen name
        """
        member = TheBoardMember.objects.get(pk=screen_name)
        if not member:
            raise MemberNotFound(screen_name)
        json_string = member.passphrase
        encrypted_passphrase = json.loads(json_string)
        passphrase = decrypt_message(encrypted_passphrase['ciphertext'], encrypted_passphrase['nonce'])
        if passphrase != password:
            raise InvalidPassword()

        # Generate the signature
        fields = [
            member.public_id,
            member.enclave_key,
        ]
        signature = sign_message(member.signing_key, password, fields)

        # Send the post request
        initiate_authentication = {"publicId": member.public_id, "enclaveKey": member.enclave_key,
                                    "signature": signature}
        url = f'{self.back_end_host}/authenticate'
        response = requests.post(url, json=initiate_authentication)
        # Check for HTTP errors
        response.raise_for_status()
        # Get the response JSON
        authenticated = response.json()

        # Validate the signature
        fields = [authenticated['sessionId'], authenticated['sessionKey']]
        # Raises exception on invalid signature
        validate_signature(member.server_signing_key, fields, authenticated['signature'])
        if not authenticated['success']:
            return {'authenticated': False}
        else:
            return {'authenticated': True, 'session_id': authenticated['sessionId'],
                    'session_key': authenticated['sessionKey']}


    def logout(self, screen_name, session_id):
        """
        Logs out the given screen_name and session_id.
        :param screen_name: The screen_name to logout.
        :type screen_name: str
        :param session_id: The session_id to logout.
        :type session_id: str
        :return: The original session ID
        :rtype: dict
        :raises MemberNotFound: If the member object cannot be found using the screen name
        :raises Exception: If the session ID provided does not match the session ID from the back end
        """
        member = TheBoardMember.objects.get(pk=screen_name)
        if not member:
            raise MemberNotFound(screen_name)

        fields = [member.public_id, session_id]
        signature = sign_message(member.signing_key, member.passphrase, fields)

        initiate_logout = {"publicId": member.public_id, "sessionId": session_id, "signature": signature}
        url = f'{self.back_end_host}/logout'
        response = requests.post(url, json=initiate_logout)
        # Check for HTTP errors
        response.raise_for_status()
        # Get the response JSON
        logged_out = response.json()
        fields = [logged_out['sessionId']]
        validate_signature(member.server_signing_key, fields, logged_out['signature'])
        if logged_out['sessionId'] != session_id:
            raise SessionIdMismatch("Session ID mismatch")

        return {'sessionId': session_id}

