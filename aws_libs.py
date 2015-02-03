import codecs
import sys, os, hashlib, hmac


class Signer:
    def __init__(self):
        # Read AWS access key from env. variables or configuration file
        self.access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        self.secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        if self.access_key is None or self.secret_key is None:
            print('No access key is available.')
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
        l = []
        # f=open(file_path, 'rb')
        count = 0
        totlen = float(os.path.getsize(file_path))
        for data in fileChunkGenerator(file_path):
            l.append(hashlib.sha256(data).digest())
            count += len(data)
            print('%i %%' % (count * 100 / totlen))
        # f.close()
        # print "root built"
        # print build_tree_from_root(l)[-1][0].encode("hex")
        return build_tree_from_root(l)[-1][0].encode("hex")


def tree_hash(file_path, start, bytes_number):
    """
    Evaluates the amazon tree hash of a portion of a file
    :rtype : string
    :param file_path: path of the file to hash
    :param start: starting position of the file chunk to hash
    :param bytes_number: size in bytes of the chunk (taken from the starting position)
    :return: the tree hash of the required part
    """
    l = []
    for data in chunk_reader(file_path, start, bytes_number, callback_function=None):
        l.append(hashlib.sha256(data).digest())
    #return build_tree_from_root(l)[-1][0].encode("hex")
    tree_hash_root = build_tree_from_root(l)[-1][0]
    return codecs.encode(tree_hash_root, 'hex').decode()

def build_tree_from_root(root, parent=None):
    # print root
    if not parent:
        parent = [root]
    if len(root) < 2:
        return parent
    current = []
    even = root[::2]
    odd = root[1::2] + [None]
    for e in zip(even, odd):
        if e[1]:
            h = hashlib.sha256(e[0])
            h.update(e[1])
            current.append(h.digest())
        else:
            current.append(e[0])
    parent.append(current)
    return build_tree_from_root(current, parent)


def fileChunkGenerator(file_path, chunk_size=1048576,
                       callback_function=None):  # =lambda x,y,z: sys.stdout.write(str(float(y)/z)+'\n') ): # 1048576 = 1Mb
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


def chunk_reader(file_path, start_position, chunk_size, subchunk_size=2**20, callback_function=None):
    """Read <chunk_size> bytes of the input file starting from <start_position>.
    This function calls the <callback_function> after each subchunk of data is uploaded"""
    total_size = os.path.getsize(file_path)
    file_object = open(file_path, 'rb')
    file_object.seek(start_position)
    current_position = start_position
    while True:
        # exit if enough data was read
        if current_position-start_position >= chunk_size:
            break
        # print(min(subchunk_size, start_position + chunk_size - current_position))
        data = file_object.read(min(subchunk_size, start_position + chunk_size - current_position))
        # print len(data)
        if not data:
            file_object.close()
            break
        yield data
        current_position = file_object.tell()
        # print(data)
        if callback_function:
            callback_function(file_path, current_position - start_position, chunk_size)
    file_object.close()
    raise StopIteration()
