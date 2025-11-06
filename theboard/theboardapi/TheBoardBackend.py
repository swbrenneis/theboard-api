import requests

from crypto import generate_member, get_ecc_publicKey, validate_signature, sign_message
from .exceptions.ScreenNameInUse import ScreenNameInUse
from .exceptions.MemberNotFound import MemberNotFound
from .exceptions.InvalidPassword import InvalidPassword
from .models import TheBoardMember


class TheBoardBackend:
    """ Encapsulates the back end API methods for accessing the board enclave """

    back_end_host = 'http://ec2-54-156-226-233.compute-1.amazonaws.com:8446'

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
        member = generate_member(screen_name)
        public_key_pem = get_ecc_publicKey(member.signing_key, member.password)

        url = f'{self.back_end_host}/register'
        initiate_registration = {"screenName": f"{screen_name}", 'signingKey': f"{public_key_pem}"}
        # Send post request
        response = requests.post(url, json=initiate_registration)
        # Check for HTTP errors
        response.raise_for_status()
        # Decode response
        registered = response.json()
        # Validate the message signature, will raise InvalidSignature on failure
        server_signing_key_pem = registered['signingPublicKey']
        fields = [
            registered["publicId"],
            registered['enclaveKey'],
            registered['signingPublicKey'],
            registered['status']
        ]
        validate_signature(server_signing_key_pem, fields, registered['signature'])
        if not registered['success']:
            if registered['status'] == "Screen exists":
                raise ScreenNameInUse("Screen name in use")
            else:
                raise Exception(registered['status'])
        else:
            member.public_id = registered['publicId']
            member.enclave_key = registered['enclaveKey']
            member.server_signing_key = server_signing_key_pem
            member.save()
            return member.passphrase

    def login(self, screen_name, password):
        member = TheBoardMember.objects.get(pk=screen_name)
        if not member:
            raise MemberNotFound(screen_name)
        # TODO Handle encrypted password
        if member.passphrase != password:
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
        member = TheBoardMember.objects.get(pk=screen_name)
        if not member:
            raise MemberNotFound(screen_name)

        fields = [member.public_id, session_id]
        signature = sign_message(member.signing_key, member.passphrase, fields)

        initiate_logout = {"publicId": member.public_id, "sessionId": session_id}
        url = f'{self.back_end_host}/logout'
        response = requests.post(url, json=initiate_logout)
        # Check for HTTP errors
        response.raise_for_status()
        # Get the response JSON
        logged_out = response.json()

