import sys, os, hashlib, hmac


class Signer:

	def __init__(self):
		# Read AWS access key from env. variables or configuration file
		self.access_key = os.environ.get('AWS_ACCESS_KEY_ID')
		self.secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
		if self.access_key is None or self.secret_key is None:
			print 'No access key is available.'
			sys.exit()
		self.algorithm = 'AWS4-HMAC-SHA256' 
	
	def getAccessKey(self):
		return self.access_key
		
	# Key derivation functions. See:
	# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
	def sign(self, key, msg):
		return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
	
	def signHex(self, key, msg):
		return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).hexdigest()

		
	def getSignatureKey(self, dateStamp, regionName, serviceName):
		kDate = self.sign(('AWS4' + self.secret_key).encode('utf-8'), dateStamp)
		kRegion = self.sign(kDate, regionName)
		kService = self.sign(kRegion, serviceName)
		kSigning = self.sign(kService, 'aws4_request')
		return kSigning
		
	def hashHex(self, content):
		return hashlib.sha256(content).hexdigest()	
		
	def treeHash(self, file_path):
		l=[]
		# f=open(file_path, 'rb')
		count = 0
		totlen = float(os.path.getsize(file_path))
		for data in fileChunkGenerator(file_path):
			l.append(hashlib.sha256(data).digest())
			count +=len(data)
			print('%i %%' %(count*100/totlen))
		# f.close()
		print "root built"
		print buildTreeFromRoot(l)[-1][0].encode("hex")
		
def buildTreeFromRoot(root, L=None):
	# print root
	if not L:
		L=[root]
	if len(root) < 2:
		return L
	l = []
	even=root[::2]
	odd=root[1::2]+[None]
	for e in zip(even, odd):
		if e[1]:
			h=hashlib.sha256(e[0])
			h.update(e[1])
			l.append(h.digest())
		else:
			l.append(e[0])
	L.append(l)
	return buildTreeFromRoot(l, L)
	
def fileChunkGenerator(file_path, chunk_size=1048576, callback_function=None): #=lambda x,y,z: sys.stdout.write(str(float(y)/z)+'\n') ): # 1048576 = 1Mb
	total_size = os.path.getsize(file_path)
	# print total_size
	file_object = open(file_path, 'rb')
	while True:
		data = file_object.read(chunk_size)
		# print len(data)
		if not data:
			file_object.close()
			break
		yield data
		if callback_function:
			callback_function(file_path, len(data), total_size)
	raise StopIteration()
