"""The Bocal Lightweight Interface for Humans main class."""

import hmac
import json
import requests

from hashlib import sha512
from urllib.parse import urljoin


class Blih:

    VERSION = 2.0
    USER_AGENT = 'blih-' + '2.0'
    ENDPOINT = 'https://blih.epitech.eu/' + str(VERSION)

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

        args = (args[0], urljoin(self.ENDPOINT, args[1])) + args[2:]

        # Set sane defaults.
        kwargs['json'] = self.sign(kwargs.get('data', None))
        kwargs['headers'] = kwargs.get('headers', {})
        kwargs['headers']['User-Agent'] = self.USER_AGENT
        kwargs['headers']['Content-Type'] = 'application/json'

        r = requests.request(*args, **kwargs)

        return r.json()

    def whoami(self):
        """Returns details about the logged in user."""

        json = self.request('GET', '/whoami')

        if 'message' in json:
            return {'username': json['message']}

        return json

    def repositories(self):
        """Returns the list of repositories created by the logged in user."""

        json = self.request('GET', '/repositories')

        if 'repositories' in json:
            return json['repositories']

        return json

    def ssh_keys(self):
        """Returns the list of SSH keys uploaded by the logged in user."""

        return self.request('GET', '/sshkeys')
