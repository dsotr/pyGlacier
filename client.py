import requests, requests_toolbelt
from aws_libs import Signer
import urllib, datetime

class GlacierParams:
	
	# Defaults
	API_VERSION = '2012-06-01'
	SERVICE		= 'glacier'
	# Static attribute names
	METHOD 		= 'METHOD'
	URI 		= 'URI'
	REQ_PARAM 	= 'REQ_PARAM'
	HEADERS 	= 'HEADERS'
	PAYLOAD 	= 'PAYLOAD'
	AMZDATETIME = 'AMZDATETIME'
	DATE 		= 'DATE'
	
	def __init__(self):
		self.params = dict()
		self.param[REQ_PARAM] = dict()
		self.param[HEADERS] = dict()
		self.param[PAYLOAD] = ''
		
	def set(self, key, value):
		# key should be one of the static variables listed above
		self.params[key] = value
	
	def get(self, key):
		return self.params.get(key, None)
	
	def updateParams(self, d):
		self.params.update(d)
	
	def replaceParams(self, d):
		self.params = d
	
	def getParams(self):
		return self.params
	
	def addToDict(self, key, dict_key, dict_value):
		self.param.setdefault(key, {})[dict_key] = dict_value

class Client:

	def __init__(self):
		self.signer 			= Signer()
		# self.service 			= 'glacier'
		self.region 			= 'us-east-1'
		self.host 				= 'glacier.%s.amazonaws.com' %self.region
		# self.api_version 		= '2012-06-01'
		# self.request_parameters = {'Version': self.api_version}
		# self.headers 			= {'Host': self.host, 	'x-amz-glacier-version': GlacierParams.API_VERSION, }
		self.payload 			= ''
		self.amzdatetime = self.datestamp = None
		self.method = None
		self.canonical_uri = None

	def makeDates(self):
		# Create a date for headers and the credential string
		t = datetime.datetime.utcnow()
		amzdatetime = t.strftime('%Y%m%dT%H%M%SZ')
		datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope
		return (amzdatetime, datestamp)
	
	def makeCanonicalQueryString(self, param):
		return urllib.urlencode(sorted(tuple(param.get(REQ_PARAM).items())))
	
	def makeCanonicalHeaders(self, param):
		param.set('HEADERS', {
			'x-amz-date': GlacierParams.AMZDATETIME,
			'Host': self.host,
			'x-amz-glacier-version': GlacierParams.API_VERSION,
		})
		return '\n'.join([':'.join(e) for e in sorted(tuple(param.get('HEADERS').items()))]) + '\n'
	
	def makeCanonicalRequest(self, param):
		canonical_request_content = [
			# self.method, 
			# self.canonical_uri, 
			# self.makeCanonicalQueryString(), 
			# self.makeCanonicalHeaders(param), 
			# self.makeSignedHeaders(), 
			# self.signer.hashHex(self.payload) 
			param.get(GlacierParams.METHOD),
			param.get(GlacierParams.URI),
			self.makeCanonicalQueryString(param), 
			self.makeCanonicalHeaders(param), 
			self.makeSignedHeaders(), 
			self.signer.hashHex(param.get(GlacierParams.PAYLOAD)),
		]
		return '\n'.join(canonical_request_content)
		
	def makeSignedHeaders(self):
		# Fixed list of headers to sign (minimal list)
		header_list = ['host','x-amz-date','x-amz-glacier-version']
		return ';'.join(sorted(header_list))
	
	def makeCredentialScope(self):
		credential_scope = '/'.join([self.datestamp, self.region, GlacierParams.SERVICE, 'aws4_request'])
		return credential_scope
	
	def makeStringToSign(self):
		string_to_sign = '\n'.join([self.signer.algorithm, self.amzdatetime, self.makeCredentialScope(), self.signer.hashHex(self.makeCanonicalRequest())])
		print string_to_sign
		return string_to_sign
	
	def makeSignature(self):
		signing_key = self.signer.getSignatureKey(self.datestamp, self.region, GlacierParams.SERVICE)
		# Sign the string_to_sign using the signing_key
		signature = self.signer.signHex(signing_key, self.makeStringToSign())
		return signature
	
	def makeAuthorizationHeader(self):
		authorization_header = self.signer.algorithm + ' ' + 'Credential=' + self.signer.getAccessKey() + '/' + self.makeCredentialScope() + ', ' +  'SignedHeaders=' + self.makeSignedHeaders() + ', ' + 'Signature=' + self.makeSignature()
		return authorization_header
		
	def listVaults(self):
		param = GlacierParams()
		# self.method = 'GET'
		param.set(GlacierParams.METHOD, 'GET')
		# self.canonical_uri = '/-/vaults'
		param.set(GlacierParams.URI, '/-/vaults')
		# self.amzdatetime, self.datestamp = self.makeDates()
		dates = self.makeDates()
		param.set(GlacierParams.AMZDATETIME, dates[0])
		param.set(GlacierParams.DATE, dates[1])
		
		endpoint = 'https://%s/-/vaults' %self.host
		request_url = endpoint + '?' + self.makeCanonicalQueryString(param)
		# self.headers['Authorization'] = self.makeAuthorizationHeader()
		param.addToDict(GlacierParams.HEADERS, 'Authorization', self.makeAuthorizationHeader())
		
		print self.headers
		print '\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++'
		print 'Request URL = ' + request_url
		r = requests.get(request_url, headers=self.headers)
		print '\nRESPONSE++++++++++++++++++++++++++++++++++++'
		print 'Response code: %d\n' % r.status_code
		print r.text