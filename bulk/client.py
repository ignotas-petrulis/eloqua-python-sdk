import time
import requests
import logging

from base64 import b64encode
from requests.exceptions import RequestException
from urllib.parse import urlencode

logger = logging.getLogger('eloqua.client')


class EloquaException(Exception):
    error_description = None
    error = None

    def __init__(self, exc={'error_description': None, 'erorr': None}):
        self.error_description = exc['error_description']
        self.error = exc['error']

    def __str__(self):
        return "Eloqua API Error {}: {}".format(
            self.error, self.error_description)


LOGIN_URL = 'https://login.eloqua.com'


class Eloqua(object):

    access_token = None
    expires_in = None
    token_type = None
    refresh_token = None

    def __init__(self, company, username, password, client_id, client_secret):
        self.valid_until = None
        self.base_url = None
        self.company = company
        self.username = username
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret

    def execute(self, method, *args, **kwargs):
        result = None
        for i in range(0, 3):
            try:
                method_map = {
                    'create_activity_export': self.create_activity_export,
                    'create_export_sync': self.create_export_sync,
                    'check_sync_status': self.check_sync_status,
                    'get_synced_data': self.get_synced_data
                }
                result = method_map[method](*args, **kwargs)
            except EloquaException as e:
                if e.code in ['403']:
                    self.authenticate()
                    continue
                else:
                    raise Exception({'message': e.message, 'code': e.code})
            break
        return result

    def buildHeaders(self):

        headers = {
            'Content-Type': 'application/json',
            'Authorization': "{token_type} {access_token}".format(
                token_type=self.token_type, access_token=self.access_token)
        }
        return headers

    def authenticate(self):
        if self.valid_until is not None and \
                self.valid_until - time.time() >= 60:
            return

        basic_auth = b64encode('{client_id}:{client_secret}'.format(
            client_id=self.client_id, client_secret=self.client_secret))

        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Basic {auth}'.format(auth=basic_auth)
        }

        data = {
            'grant_type': 'password',
            'scope': 'full',
            'username': '{company}\\{username}'.format(
                company=self.company, username=self.username),
            'password': self.password
        }

        resp = self.post('{login_url}/auth/oauth2/token'.format(
            login_url=LOGIN_URL), data, headers)

        self.access_token = resp['access_token']
        self.token_type = resp['token_type']
        self.expires_in = resp['expires_in']
        self.refresh_token = resp['refresh_token']
        self.valid_until = time.time() + resp['expires_in']

    def create_activity_export(self, name, fields=None, filter=None):
        self.authenticate()

        data = {
            'name': name,
            'fields': fields,
            'filter': filter
        }

        headers = self.buildHeaders()

        resp = self.post('https://secure.p03.eloqua.com/API/Bulk/2.0/' +
                         'activities/exports', data, headers)

        return resp

    def create_export_sync(self, synced_instance_uri, callback_url=None):
        self.authenticate()

        data = {
            'syncedInstanceUri': synced_instance_uri,
            'callbackUrl': callback_url
        }

        headers = self.buildHeaders()
        resp = self.post('https://secure.p03.eloqua.com/API/Bulk/2.0/' +
                         'syncs', data, headers)
        return resp

    def check_sync_status(self, sync_uri):

        headers = {
            'Accept': 'application/json',
            'Authorization': "{token_type} {access_token}".format(
                token_type=self.token_type, access_token=self.access_token)
        }

        resp = self.get('https://secure.p03.eloqua.com/API/Bulk/2.0' +
                        sync_uri, headers)
        return resp

    def get_synced_data(self, sync_uri, offset, batch_size):

        headers = {
            'Accept': 'application/json',
            'Authorization': "{token_type} {access_token}".format(
                token_type=self.token_type, access_token=self.access_token)
        }
        response = self.get('https://secure.p03.eloqua.com/API/Bulk/2.0' +
                            sync_uri + '/data?limit=' + str(batch_size) +
                            '&offset=' + str(offset), headers)
        return response

    def make_request(self, **kwargs):
        logger.info(u'{method} Request: {url}'.format(**kwargs))
        if kwargs.get('json'):
            logger.info('payload: {json}'.format(**kwargs))

        resp = requests.request(**kwargs)

        logger.info(u'{method} response: {status} {text}'.format(
                    method=kwargs['method'],
                    status=resp.status_code,
                    text=resp.text))

        return resp

    def post(self, url, data=None, headers=None):
        try:
            r = self.make_request(**dict(
                method='POST',
                url=url,
                json=data,
                headers=headers
            ))
        except RequestException as e:
            raise e
        else:
            if r.status_code >= 400:
                raise EloquaException(r.json())
            if r.status_code == 204:
                return None
            return r.json()

    def get(self, url, headers=None, **queryparams):

        if len(queryparams):
            url += '?' + urlencode(queryparams)

        try:
            r = self.make_request(**dict(
                method='GET',
                url=url,
                headers=headers
            ))
        except RequestException as e:
            raise e
        else:
            if r.status_code >= 400:
                raise EloquaException(r.json())
            return r.json()
