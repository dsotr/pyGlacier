import urllib.parse
import datetime
import os

import requests

from aws_libs import Signer

# see https://github.com/shazow/urllib3/issues/497#issuecomment-66942891 to understand the following line
# requests.packages.urllib3.disable_warnings()


class GlacierParams:
    # Defaults
    API_VERSION = '2012-06-01'
    SERVICE = 'glacier'
    DEFAULT_PART_SIZE = str(2 ** (20 + 8))  # 268435456 = 256Mb
    # Static attribute names
    METHOD = 'METHOD'
    URI = 'URI'
    REQ_PARAM = 'REQ_PARAM'
    HEADERS = 'HEADERS'
    PAYLOAD = 'PAYLOAD'
    AMZDATETIME = 'AMZDATETIME'
    DATE = 'DATE'

    def __init__(self):
        self.params = dict()
        self.params[GlacierParams.REQ_PARAM] = dict()
        self.params[GlacierParams.HEADERS] = dict()
        self.params[GlacierParams.PAYLOAD] = ''.encode('utf-8')

    def set(self, key, value):
        # key should be one of the static variables listed above
        self.params[key] = value

    def set_header(self, key, value):
        # key should be one of the static variables listed above
        self.add_to_dict(GlacierParams.HEADERS, key, value)
        # self.params[GlacierParams.HEADERS][key] = value
        # print self.params

    def get(self, key):
        return self.params.get(key, None)

    def update_params(self, d):
        self.params.update(d)

    def replace_params(self, d):
        self.params = d

    def get_params(self):
        return self.params

    def add_to_dict(self, key, dict_key, dict_value):
        # print "Add to dict KEY: %s %s %s" %( key, dict_key, dict_value)
        # print "before add to dict" + str(self.params)
        self.params.setdefault(key, {})[dict_key] = dict_value
        # print "After add to dict" + str(self.params)

    def make_dates(self):
        # Create a date for headers and the credential string
        t = datetime.datetime.utcnow()
        self.set(GlacierParams.AMZDATETIME, t.strftime('%Y%m%dT%H%M%SZ'))
        self.set(GlacierParams.DATE, t.strftime('%Y%m%d'))


class Client:
    def __init__(self, debug=False):
        self.signer = Signer()
        # self.service 			= 'glacier'
        self.region = 'us-east-1'
        self.host = 'glacier.%s.amazonaws.com' % self.region
        # self.api_version 		= '2012-06-01'
        # self.request_parameters = {'Version': self.api_version}
        # self.headers 			= {'Host': self.host, 	'x-amz-glacier-version': GlacierParams.API_VERSION, }
        self.payload = ''
        # self.amzdatetime = self.datestamp = None
        # self.method = None
        # self.canonical_uri = None
        self.debug = debug

    def make_canonical_query_string(self, param):
        return urllib.parse.urlencode(sorted(tuple(param.get(GlacierParams.REQ_PARAM).items())))

    def make_canonical_headers(self, param):
        param.set_header('x-amz-date', param.get(GlacierParams.AMZDATETIME))
        param.set_header('host', self.host)
        param.set_header('x-amz-glacier-version', GlacierParams.API_VERSION)
        canonical_headers_list = ['host', 'x-amz-date', 'x-amz-glacier-version']
        header_list = map(lambda x: (x[0].lower().strip(), x[1].strip()),
                          filter(lambda x: x[0] in canonical_headers_list, tuple(param.get('HEADERS').items())))
        return '\n'.join([':'.join(e) for e in sorted(header_list)]) + '\n'

    def make_canonical_request(self, param):
        canonical_request_content = [  # self.method,   # self.canonical_uri,   # self.makeCanonicalQueryString(),
                                       # self.makeCanonicalHeaders(param),   # self.makeSignedHeaders(),
                                       # self.signer.hashHex(self.payload)
                                       param.get(GlacierParams.METHOD),
                                       param.get(GlacierParams.URI),
                                       self.make_canonical_query_string(param),
                                       self.make_canonical_headers(param),
                                       self.make_signed_headers(),
                                       self.signer.hashHex(param.get(GlacierParams.PAYLOAD)),
        ]
        if self.debug:
            print('Canonical String\n' + '\n'.join(canonical_request_content))
        return '\n'.join(canonical_request_content)

    def make_signed_headers(self):
        # Fixed list of headers to sign (minimal list)
        header_list = ['host', 'x-amz-date', 'x-amz-glacier-version']
        return ';'.join(sorted(header_list))

    def make_credential_scope(self, param):
        credential_scope = '/'.join([param.get(GlacierParams.DATE), self.region, GlacierParams.SERVICE, 'aws4_request'])
        return credential_scope

    def make_string_to_sign(self, param):
        string_to_sign = '\n'.join(
            [self.signer.algorithm, param.get(GlacierParams.AMZDATETIME), self.make_credential_scope(param),
             self.signer.hashHex(self.make_canonical_request(param).encode('utf-8'))])
        if self.debug:
            print("String to sign:")
            print(string_to_sign)
        return string_to_sign

    def make_signature(self, param):
        signing_key = self.signer.getSignatureKey(param.get(GlacierParams.DATE), self.region, GlacierParams.SERVICE)
        # Sign the string_to_sign using the signing_key
        signature = self.signer.signHex(signing_key, self.make_string_to_sign(param))
        return signature

    def make_authorization_header(self, param):
        authorization_header = self.signer.algorithm + ' ' + \
                               'Credential=' + self.signer.getAccessKey() + '/' + \
                               self.make_credential_scope(param) + ', ' + \
                               'SignedHeaders=' + self.make_signed_headers() + \
                               ', ' + 'Signature=' + self.make_signature(param)
        param.add_to_dict(GlacierParams.HEADERS, 'Authorization', authorization_header)
        # return authorization_header

    def list_vaults(self):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'GET')
        param.set(GlacierParams.URI, '/-/vaults')
        param.make_dates()

        endpoint = 'https://%s/-/vaults' % self.host
        request_url = endpoint + '?' + self.make_canonical_query_string(param)
        self.make_authorization_header(param)

        if self.debug:
            print('Request URL = ' + request_url)
            # print '\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++'
            # print param.get(GlacierParams.HEADERS)
        r = requests.get(request_url, headers=param.get(GlacierParams.HEADERS))
        return r

    def initiate_multipart_upload(self, multipard_desc, vault_name):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'POST')
        param.set(GlacierParams.URI, '/-/vaults/%s/multipart-uploads' % vault_name)
        param.make_dates()
        param.set_header('x-amz-archive-description', multipard_desc)
        param.set_header('x-amz-part-size', GlacierParams.DEFAULT_PART_SIZE)
        endpoint = 'https://%s%s' % (self.host, param.get(GlacierParams.URI))
        request_url = endpoint + '?' + self.make_canonical_query_string(param)
        self.make_authorization_header(param)
        if self.debug:
            print('Request URL = ' + request_url)
        r = requests.post(request_url, headers=param.get(GlacierParams.HEADERS))
        return r

    def upload_archive(self, file_path, vault_name):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'POST')
        param.set(GlacierParams.URI, '/-/vaults/%s/archives' % vault_name)
        param.make_dates()
        param.set_header('Content-Length', str(os.path.getsize(file_path)))
        param.set_header('x-amz-archive-description', self.get_archive_name(file_path))
        content = open(file_path).read()
        param.set(GlacierParams.PAYLOAD, content)
        param.set_header('x-amz-content-sha256', self.signer.hashHex(content))
        param.set_header('x-amz-sha256-tree-hash', self.signer.treeHash(file_path))
        endpoint = 'https://%s%s' % (self.host, param.get(GlacierParams.URI))
        request_url = endpoint + '?' + self.make_canonical_query_string(param)
        self.make_authorization_header(param)
        # print 'Request URL = ' + request_url
        # print param.get(GlacierParams.HEADERS)

        r = requests.post(request_url, headers=param.get(GlacierParams.HEADERS), data=content)
        print('Response code: %d\n' % r.status_code)
        return r

    def get_archive_name(self, file_path):
        """returns the archive name from the file path"""
        return os.path.basename(file_path)


if __name__ == '__main__':
    c = Client()
    # response = c.initiate_multipart_upload('test-multipart-1','Foto')
    response = c.list_vaults()
    print(response.status_code)
    print(response.text)
    print(response.headers)