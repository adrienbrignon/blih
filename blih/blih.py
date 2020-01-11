"""The Bocal Lightweight Interface for Humans main class."""

import hmac
import json
import requests

from hashlib import sha512


class Blih:

    VERSION = 2.1
    ENDPOINT = 'https://blih.epitech.eu'

    def __init__(self, username: str, password: str):
        """The class constructor."""

        self.username = username
        self.password = password
        self.token = sha512(password.encode('utf-8')).hexdigest().encode('utf-8')

    def sign(self, data=None):
        """Sign data in order to send it to the server."""

        signature = hmac.new(self.token, msg=self.username.encode('utf-8'), digestmod=sha512)

        if data:
            payload = json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))

            signature.update(payload.encode('utf-8'))

        signed_data = {'user': self.username, 'signature': signature.hexdigest()}

        if data is not None:
            signed_data['data'] = data

        return signed_data

    def request(self, *args, **kwargs):
        """Send a request to the server."""

        kwargs['data'] = self.sign(kwargs.get('data', []))

        r = requests.request(*args, **kwargs)

        return r.text
