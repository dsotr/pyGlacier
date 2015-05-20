# -*- coding: latin-1 -*-

import sys, os, hashlib, hmac, codecs, logging, settings
from util.progressbar import AnimatedProgressBar


class Signer:
    '''
    Utility class for signing requests with the amazon keys
    '''
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
    '''
    :param root: array with the hashes of each 1Mb chunk
    :param parent: used for recursion
    :return: the final tree hash byte string
    '''
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
    '''
    Converts an input byte string to its hex representation
    :param b_str: input byte string
    :return: a string with the hex representation of the input
    '''
    return codecs.encode(b_str, 'hex_codec').decode()


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
        self.logger = logging.getLogger("[ChunkFileObject]")
        # read start from keyword args (and remove it). If start is not present defaults to 0
        self.args = args
        self.start = kwds.pop('start', 0)
        # read end from keyword args (and remove it).
        self.end = kwds.pop('end', None)
        # callback function to show reading progress
        self.callback = kwds.pop('callback', None)
        # Create a file object from input args
        self.file_obj = open(*args, **kwds)
        self.mode = self.file_obj.mode
        # seek the end of file to evaluate file size
        self.file_obj.seek(0, os.SEEK_END)
        # If end is not present or too large set it to file size
        if not self.end or self.end > self.file_obj.tell():
            self.end = self.file_obj.tell()
        # reset file index to 0
        self.logger.debug('Instantiate FileChunkObject[%s-%s] with args: %s and kwywords: %s' %(self.start, self.end, args, kwds))
        self.seek(0)

    # def __len__(self):
    #     return self.end - self.start

    # def __getitem__(self, *args, **kwargs):
    #     if args and args[0]:
    #         if type(args[0]) == slice:
    #             self.logger.debug("Requested slice: %s", str(args[0]))
    #             start = args[0].start + self.start
    #             if args[0].stop:
    #                 end = self.start + args[0].stop
    #             else:
    #                 end = self.end
    #             sliced_chunk_file_object = ChunkFileObject(*self.args, start = start, end = end, callback = self.callback)
    #             return sliced_chunk_file_object

    def __iter__(self):
        self.logger.debug("call to iter method")
        return self

    def __next__(self):
        while self.tell() < self.end:
            self.logger.debug("Iterating from position %i (end=%i)", self.tell(), self.end)
            yield self.read(2**13)

    def read(self, *args, **kwargs):
        if args:
            current_cursor = self.file_obj.tell()
            read_bytes = current_cursor - self.start
            if current_cursor + int(args[0]) > self.end:
                new_args = list(args)
                new_args[0] = self.end - current_cursor
                self.logger.debug("reascaling read length from %i to %i" %(args[0], new_args[0]))
                args = tuple(new_args)
            # print('Serving %i bytes (%i - %i) from ChunkFileReader[%i-%i] read(bytes) method' %(
            #     args[0], current_cursor, current_cursor+args[0], self.start, self.end)) # TODO: replace this with a callback function
            if self.callback:
                self.callback(self.start, self.end, args[0])
            return self.file_obj.read(*args, **kwargs)
        else:
            # print("Serving %i bytes from ChunkFileReader read() method" %(self.end - self.file_obj.tell()))
            return self.file_obj.read(self.end - self.file_obj.tell())

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

    def close(self):
        return self.file_obj.close()



def progress_bar(title, start, end):
    '''
    Returns a progress bar function which displays the progress through an AnimatedProgressBar
    :param title: prefix name to display
    :param start: starting position of the file chunk
    :param end: last byte position of the file chunk
    :return: a function which displays the progress update after every call
    '''
    p = AnimatedProgressBar(start = 0, end = end - start, format=title+' [%(fill)s>%(blank)s] %(progress)s%%', width=25)

    def progress(x, y, z):
        # print(title, "%0.1f" % (float(y) / z * 100), '%', sep=' ', end='\r')  # , flush=True)
        p + z
        p.show_progress()
    return progress
