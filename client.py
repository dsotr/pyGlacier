import requests, requests_toolbelt
from aws_libs import Signer
import urllib, datetime, json, os
# see https://github.com/shazow/urllib3/issues/497#issuecomment-66942891 to understand the following line
requests.packages.urllib3.disable_warnings()

class GlacierParams:
    # Defaults
    API_VERSION = '2012-06-01'
    SERVICE = 'glacier'
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
        self.params[GlacierParams.PAYLOAD] = ''

    def set(self, key, value):
        # key should be one of the static variables listed above
        self.params[key] = value

    def setHeader(self, key, value):
        # key should be one of the static variables listed above
        self.addToDict(GlacierParams.HEADERS, key, value)
        # self.params[GlacierParams.HEADERS][key] = value
        # print self.params

    def get(self, key):
        return self.params.get(key, None)

    def updateParams(self, d):
        self.params.update(d)

    def replaceParams(self, d):
        self.params = d

    def getParams(self):
        return self.params

    def addToDict(self, key, dict_key, dict_value):
        # print "Add to dict KEY: %s %s %s" %( key, dict_key, dict_value)
        # print "before add to dict" + str(self.params)
        self.params.setdefault(key, {})[dict_key] = dict_value
        # print "After add to dict" + str(self.params)

    def makeDates(self):
        # Create a date for headers and the credential string
        t = datetime.datetime.utcnow()
        self.set(GlacierParams.AMZDATETIME, t.strftime('%Y%m%dT%H%M%SZ'))
        self.set(GlacierParams.DATE, t.strftime('%Y%m%d'))

class Client:
    def __init__(self):
        self.signer = Signer()
        # self.service 			= 'glacier'
        self.region = 'us-east-1'
        self.host = 'glacier.%s.amazonaws.com' % self.region
        # self.api_version 		= '2012-06-01'
        # self.request_parameters = {'Version': self.api_version}
        # self.headers 			= {'Host': self.host, 	'x-amz-glacier-version': GlacierParams.API_VERSION, }
        self.payload = ''
        # self.amzdatetime = self.datestamp = None
        self.method = None
        self.canonical_uri = None

    def makeCanonicalQueryString(self, param):
        return urllib.urlencode(sorted(tuple(param.get(GlacierParams.REQ_PARAM).items())))

    def makeCanonicalHeaders(self, param):
        param.setHeader('x-amz-date', param.get(GlacierParams.AMZDATETIME))
        param.setHeader('host', self.host)
        param.setHeader('x-amz-glacier-version', GlacierParams.API_VERSION)
        canonical_headers_list = ['host','x-amz-date','x-amz-glacier-version']
        header_list = map(lambda x: (x[0].lower().strip(), x[1].strip()), filter(lambda x: x[0] in canonical_headers_list, tuple(param.get('HEADERS').items())))
        return '\n'.join([':'.join(e) for e in sorted(header_list)]) + '\n'

    def makeCanonicalRequest(self, param):
        canonical_request_content = [  # self.method,   # self.canonical_uri,   # self.makeCanonicalQueryString(),
                                       # self.makeCanonicalHeaders(param),   # self.makeSignedHeaders(),
                                       # self.signer.hashHex(self.payload)
                                       param.get(GlacierParams.METHOD),
                                       param.get(GlacierParams.URI),
                                       self.makeCanonicalQueryString(param),
                                       self.makeCanonicalHeaders(param),
                                       self.makeSignedHeaders(),
                                       self.signer.hashHex(param.get(GlacierParams.PAYLOAD)),
        ]
        print 'Canonical String\n'+'\n'.join(canonical_request_content)+'\n'
        return '\n'.join(canonical_request_content)

    def makeSignedHeaders(self):
        # Fixed list of headers to sign (minimal list)
        header_list = ['host', 'x-amz-date', 'x-amz-glacier-version']
        return ';'.join(sorted(header_list))

    def makeCredentialScope(self, param):
        credential_scope = '/'.join([param.get(GlacierParams.DATE), self.region, GlacierParams.SERVICE, 'aws4_request'])
        return credential_scope

    def makeStringToSign(self, param):
        string_to_sign = '\n'.join(
            [self.signer.algorithm, param.get(GlacierParams.AMZDATETIME), self.makeCredentialScope(param),
             self.signer.hashHex(self.makeCanonicalRequest(param))])
        print "String to sign:"
        print string_to_sign
        return string_to_sign

    def makeSignature(self, param):
        signing_key = self.signer.getSignatureKey(param.get(GlacierParams.DATE), self.region, GlacierParams.SERVICE)
        # Sign the string_to_sign using the signing_key
        signature = self.signer.signHex(signing_key, self.makeStringToSign(param))
        return signature

    def makeAuthorizationHeader(self, param):
        authorization_header = self.signer.algorithm + ' ' + \
                               'Credential=' + self.signer.getAccessKey() + '/' + \
                               self.makeCredentialScope(param) + ', ' + \
                               'SignedHeaders=' + self.makeSignedHeaders() + \
                               ', ' + 'Signature=' + self.makeSignature(param)
        param.addToDict(GlacierParams.HEADERS, 'Authorization', authorization_header)
        # return authorization_header

    def listVaults(self):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'GET')
        param.set(GlacierParams.URI, '/-/vaults')
        param.makeDates()

        endpoint = 'https://%s/-/vaults' % self.host
        request_url = endpoint + '?' + self.makeCanonicalQueryString(param)
        self.makeAuthorizationHeader(param)

        #print param.get(GlacierParams.HEADERS)
        # print '\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++'
        print 'Request URL = ' + request_url
        r = requests.get(request_url, headers=param.get(GlacierParams.HEADERS))
        # print '\nRESPONSE++++++++++++++++++++++++++++++++++++'
        #print 'Response code: %d\n' % r.status_code
        return r.text

    def initiate_multipart_upload(self, file_path):
        pass

    def upload_archive(self, file_path, vault_name):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'POST')
        param.set(GlacierParams.URI, '/-/vaults/%s/archives' %vault_name)
        param.makeDates()
        param.setHeader('Content-Length', str(os.path.getsize(file_path)))
        param.setHeader('x-amz-archive-description', self.get_archive_name(file_path))
        content = open(file_path).read()
        param.set(GlacierParams.PAYLOAD, content)
        param.setHeader('x-amz-content-sha256', self.signer.hashHex(content))
        param.setHeader('x-amz-sha256-tree-hash', self.signer.treeHash(file_path))
        endpoint = 'https://%s%s' % (self.host, param.get(GlacierParams.URI))
        request_url = endpoint + '?' + self.makeCanonicalQueryString(param)
        self.makeAuthorizationHeader(param)
        # print 'Request URL = ' + request_url
        # print param.get(GlacierParams.HEADERS)

        r = requests.post(request_url, headers=param.get(GlacierParams.HEADERS), data=content, timeout=20)
        print 'Response code: %d\n' % r.status_code
        return r

    def get_archive_name(selfself, file_path):
        '''returns the archive name from the file path'''
        return os.path.basename(file_path)

if __name__=='__main__':
    c=Client()
    response = c.upload_archive('test-upload.txt','Foto')
    print response.text
    print response.headers

    #print json.dumps(json.loads(c.listVaults()), sort_keys=True, indent=4, separators=(',', ': '))
