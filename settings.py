# -*- coding: latin-1 -*-

import datetime, time
#from aws_libs import ChunkFileObject

# Available glacier regions
REGIONS = {
    'us-east-1': 'US EAST (N. VIRGINIA)',
    'us-west-2': 'US WEST (OREGON)',
    'us-west-1': 'US WEST (N. CALIFORNIA)',
    'eu-west-1': 'EU (IRELAND)',
    'eu-central-1': 'EU (FRANKFURT)',
    'ap-southeast-2': 'ASIA PACIFIC (SYDNEY)',
    'ap-northeast-1': 'ASIA PACIFIC (TOKYO)',
}

# glacier API version
API_VERSION = '2012-06-01'
# Service name
SERVICE = 'glacier'
# Default size of each part in a multipart upload
DEFAULT_PART_SIZE = 2 ** (20 + 7)  #  128Mb
#DEFAULT_PART_SIZE = 2 ** (20 + 1)  # 2Mb
TREE_HASH_PART_SIZE = 2 ** 20 # 1Mb

class GlacierParams:
    # Static attribute names
    METHOD = 'METHOD'
    URI = 'URI'
    REQ_PARAM = 'REQ_PARAM'
    HEADERS = 'HEADERS'
    PAYLOAD = 'PAYLOAD'
    PAYLOAD_CONTENT = 'PAYLOAD_CONTENT'
    AMZDATETIME = 'AMZDATETIME'
    DATE = 'DATE'
    CANONICAL_STRING_HASH = 'CANONICAL_STRING_HASH'

    def __init__(self):
        """
        This class stores the parameters needed by the GlacierClient methods. It's basically a dictionary.
        """
        self.params = dict()
        self.params[GlacierParams.REQ_PARAM] = dict()
        self.params[GlacierParams.HEADERS] = dict()
        self.params[GlacierParams.PAYLOAD] = None # At runtime, this will store a ChunkFileObject
        self.make_dates()

    def set(self, key, value):
        # key should be one of the static variables listed above
        self.params[key] = value

    def set_header(self, key, value):
        # key should be one of the static variables listed above
        self.add_to_dict(GlacierParams.HEADERS, key, value)

    def get(self, key):
        return self.params.get(key, None)

    def update_params(self, d):
        self.params.update(d)

    def replace_params(self, d):
        self.params = d

    def get_params(self):
        return self.params

    def add_to_dict(self, key, dict_key, dict_value):
        """updates a dictionary (accessed through the first key) with the
        supplied key/value pair, creating a new dictionary if needed"""
        self.params.setdefault(key, {})[dict_key] = dict_value

    def make_dates(self):
        """Create a date for headers and the credential string"""
        t = datetime.datetime.utcnow()
        self.set(GlacierParams.AMZDATETIME, t.strftime('%Y%m%dT%H%M%SZ'))
        self.set(GlacierParams.DATE, t.strftime('%Y%m%d'))

    def get_payload_content(self):
        ''' Read payload data and ?brings the cursor back to 0 so that it can be used again
        '''
        if self.get(GlacierParams.PAYLOAD_CONTENT):
            return self.get(GlacierParams.PAYLOAD_CONTENT)
        payload = self.get(GlacierParams.PAYLOAD)
        if not payload:
            # return None
            return b''
        if type(payload) == str:
            content = payload
        elif hasattr(payload, 'read'):
            content = payload.read()
            payload.seek(0)
        else:
            content = None
        self.set(GlacierParams.PAYLOAD_CONTENT, content)
        return content

    def get_canonical_string_hash(self):
        return self.get(GlacierParams.CANONICAL_STRING_HASH)
