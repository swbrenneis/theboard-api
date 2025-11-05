import requests

from crypto import generate_member, get_ecc_publicKey

class TheBoardBackend:
    """ Encapsulates the back end API methods for accessing the board enclave """

    back_end_host = 'http://ec2-54-156-226-233.compute-1.amazonaws.com:8446'

    def register(self, screen_name):
        member = generate_member(screen_name)
        public_key_pem = get_ecc_publicKey(member.signing_key, member.password)

        url = f'{self.back_end_host}/register'
        initiate_registration = {"screenName": f"{screen_name}", 'signingKey': f"{public_key_pem}"}
        # Send post request
        response = requests.post(url, json=initiate_registration)
        # Check for HTTP errors
        response.raise_for_status()
        # Decode response
        data = response.json()
        if not data['success']:
            pass


    def login(self, screen_name, password):
        pass

    def logout(self, screen_name):
        pass