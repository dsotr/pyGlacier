# -*- coding: latin-1 -*-

import sys, os, hashlib, hmac, codecs, logging, settings


class Signer:
    def __init__(self):
        # Read AWS access key from env. variables or configuration file
        self.access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        self.secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        if self.access_key is None or self.secret_key is None:
            logging.critical('No access key is available.')
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
        if type(content) is str:
            return hashlib.sha256(content.encode('utf-8')).hexdigest()
        else:
            return hashlib.sha256(content).hexdigest()

    # def treeHash(self, file_path):
    #     l = []
    #     # f=open(file_path, 'rb')
    #     count = 0
    #     totlen = float(os.path.getsize(file_path))
    #     for data in fileChunkGenerator(file_path):
    #         l.append(hashlib.sha256(data).digest())
    #         count += len(data)
    #         logging.info('%i %%' % (count * 100 / totlen))
    #     # f.close()
    #     # print "root built"
    #     # print build_tree_from_root(l)[-1][0].encode("hex")
    #     return build_tree_from_root(l)[-1][0].encode("hex")


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
    #reader = ChunkReader(file_path, start, bytes_number, callback_function=progress_bar("Tree hash"))
    chunk_file = ChunkFileObject(file_path, 'rb', start = start, end = start + bytes_number )
    # g = reader.get_chunk_generator()
    # for data in g:
    #     l.append(hashlib.sha256(data).digest())
    while True:
        data = chunk_file.read(settings.TREE_HASH_PART_SIZE)
        if data:
            l.append(hashlib.sha256(data).digest())
        else:
            break
    # return build_tree_from_root(l)[-1][0].encode("hex")
    tree_hash_root = build_tree_from_root(l)[-1][0]
    return tree_hash_root
    # return codecs.encode(tree_hash_root, 'hex').decode()


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


def bytes_to_hex(b_str):
    return codecs.encode(b_str, 'hex_codec').decode()


# def fileChunkGenerator(file_path, chunk_size=1048576,
#                        callback_function=None):  # =lambda x,y,z: sys.stdout.write(str(float(y)/z)+'\n') ): # 1048576 = 1Mb
#     total_size = os.path.getsize(file_path)
#     # print total_size
#     file_object = open(file_path, 'rb')
#     while True:
#         data = file_object.read(chunk_size)
#         # print len(data)
#         if not data:
#             file_object.close()
#             break
#         yield data
#         if callback_function:
#             callback_function(file_path, len(data), total_size)
#     raise StopIteration()


# class ChunkReader():
#     """Read <chunk_size> bytes of the input file starting from <start_position>.
#     The <callback_function> is called after each subchunk of data is uploaded"""
#
#     def __init__(self, file_path, start_position, chunk_size, subchunk_size=2 ** 20, callback_function=None):
#         self.file_path = file_path
#         self.start_position = start_position
#         if chunk_size < 1 and self.file_path:
#             self.chunk_size = os.path.getsize(file_path)
#         else:
#             self.chunk_size = chunk_size
#         self.subchunk_size = subchunk_size
#         self.callback_function = callback_function
#
#     def get_chunk_generator(self):
#         """Return a generator that reads <chunk_size> bytes of the input file starting from <start_position>.
#         This function calls the <callback_function> after each subchunk of data is generated"""
#         if not self.file_path:
#             return ''
#
#         def chunk_generator():
#             total_size = os.path.getsize(self.file_path)
#             file_object = open(self.file_path, 'rb')
#             file_object.seek(self.start_position)
#             current_position = self.start_position
#             # print("Start pos=%i, Current pos=%i, Chunk Size=%i", self.start_position, current_position, self.chunk_size)
#             while True:
#                 # exit if enough data was read
#                 if current_position - self.start_position >= self.chunk_size:
#                     break
#                 # print(min(subchunk_size, start_position + chunk_size - current_position))
#                 data = file_object.read(
#                     min(self.subchunk_size, self.start_position + self.chunk_size - current_position))
#                 # print len(data)
#                 if not data:
#                     file_object.close()
#                     break
#                 yield data
#                 current_position = file_object.tell()
#                 # print(data)
#                 if self.callback_function:
#                     self.callback_function(self.file_path, current_position - self.start_position, self.chunk_size)
#             file_object.close()
#             raise StopIteration()
#
#         return chunk_generator()
#
#     def get_data(self):
#         if not self.file_path:
#             return b""
#         file_object = open(self.file_path, 'rb')
#         file_object.seek(self.start_position)
#         data = file_object.read(self.chunk_size)
#         file_object.close()
#         return data


class ChunkFileObject(object):
    """
    This is a file-type object. it reads a file from the file system and behaves in the same way as the open() function.
    In addition, a range can be set (start, end) using the set_range method. This operation restricts the object
    to the bytes of the file included in that range.
    If a range is set using the set_range method, the class behaves as if a smaller file
    (containing only bytes from start to end) was provided.
    :param args: the same parameters as the open() function
    :param kwds:    start = starting byte
                    end   = last byte
                    the same parameters as the open() function. 'start' and 'end' are removed if present
    """

    def __init__(self, *args, **kwds):
        logging.debug('Instantiate FileChunkObject with args: %s and kwywords: %s' %(args, kwds))
        # read start from keyword args (and remove it). If start is not present defaults to 0
        self.start = kwds.pop('start', 0)
        # read end from keyword args (and remove it).
        self.end = kwds.pop('end', None)
        # Create a file object from input args
        self.file_obj = open(*args, **kwds)
        # If end is not present defaults to file size
        if not self.end:
            # seek the end of file to evaluate file size
            self.file_obj.seek(0, os.SEEK_END)
            self.end = self.file_obj.tell()
        # reset file index to 0
        self.file_obj.seek(0)

    def __enter__(self):
        return self.file_obj

    def __exit__(self, *args):
        print('done')
        self.file_obj.close()

    def read(self, *args, **kwargs):
        if args:
            current_cursor = self.file_obj.tell()
            read_bytes = current_cursor - self.start
            if self.start + read_bytes + int(args[0]) > self.end:
                new_args = list(args)
                new_args[0] = self.end - read_bytes - self.start
                logging.debug("reascaling read length from %i to %i" %(args[0], new_args[0]))
                args = tuple(new_args)
            #print('read %i bytes' %args[0]) # TODO: replace this with a callback function
            return self.file_obj.read(*args, **kwargs)
        else:
             return self.file_obj.read(self.end - self.file_obj.tell()) # FIXME: self.tell or file_object.tell???

    def seek(self, *args, **kwargs):
        if args:
            new_args = list(args)
            # default whence parameter
            if len(args) < 2:
                new_args.append(os.SEEK_SET)
            if new_args[1] == os.SEEK_SET:  # Absolute file positioning
                new_args[0] = args[0] + self.start
            elif new_args[1] == os.SEEK_CUR: # Relative to current position
                new_args = [self.file_obj.tell() + args[0], os.SEEK_SET]
            elif new_args[1] == os.SEEK_END:  # Relative to end position
                if new_args[0] == 0:
                    new_args = [self.end, os.SEEK_SET]
                    return self.file_obj.seek(*new_args) - self.start
                else:  # Throw error as per python3 specs
                    return self.file_obj.seek(*new_args)
        return self.file_obj.seek(*new_args) - self.start

    def tell(self, *args, **kwargs):
        return self.file_obj.tell() - self.start

    def set_range(self, start, end):
        self.start = start
        self.end = end
        self.seek(0)

    def __getattr__(self, attr):
        # Fallback to file object method if the called method wasn't overridden
        return getattr(self.file_obj, attr)


def progress_bar(title):
    def progress(x, y, z):
        print(title, "%0.1f" % (float(y) / z * 100), '%', sep=' ', end='\r')  # , flush=True)

    return progress

if __name__=='__main__':
    fo = ChunkFileObject('testupload.txt')
    fo.set_range(0, 2340)
    s = fo.read(2000)
    s += fo.read(2000)
    print(len(s))
