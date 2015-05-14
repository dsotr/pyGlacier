# -*- coding: latin-1 -*-

import urllib.parse
import os
import sys
import requests
import settings
import logging
from settings import GlacierParams
import json

from aws_libs import Signer, tree_hash, bytes_to_hex, build_tree_from_root, progress_bar, ChunkFileObject
from logger import Logger



class GlacierClient:
    def __init__(self, region='us-east-1', debug=False):
        self.signer = Signer()
        # print(os.getcwd())
        self.logger = Logger('database.db')
        # self.service 			= 'glacier'
        if region in settings.REGIONS:
            self.region = region
        else:
            raise InvalidRegionException('Invalid region %s.\nAvailable regions: %s' % (region, str(settings.REGIONS)))
        self.host = 'glacier.%s.amazonaws.com' % self.region
        self.payload = ''
        self.debug = debug

    def make_canonical_query_string(self, param):
        return urllib.parse.urlencode(sorted(tuple(param.get(GlacierParams.REQ_PARAM).items())))

    def make_canonical_headers(self, param):
        param.set_header('x-amz-date', param.get(GlacierParams.AMZDATETIME))
        param.set_header('host', self.host)
        param.set_header('x-amz-glacier-version', settings.API_VERSION)
        canonical_headers_list = ['host', 'x-amz-date', 'x-amz-glacier-version']
        header_list = map(lambda x: (x[0].lower().strip(), x[1].strip()),
                          filter(lambda x: x[0] in canonical_headers_list, tuple(param.get('HEADERS').items())))
        canonical_header = '\n'.join([':'.join(e) for e in sorted(header_list)]) + '\n'
        logging.info('Canonical header: %s' %canonical_header)
        return canonical_header

    def make_canonical_request(self, param):
        if param.get_canonical_string_hash():
            payload_hash = param.get_canonical_string_hash()
        else:
            payload_hash = self.signer.hashHex(param.get_payload_content())
        canonical_request_content = [  # self.method,   # self.canonical_uri,   # self.makeCanonicalQueryString(),
                                       # self.makeCanonicalHeaders(param),   # self.makeSignedHeaders(),
                                       # self.signer.hashHex(self.payload)
                                       param.get(GlacierParams.METHOD),
                                       param.get(GlacierParams.URI),
                                       self.make_canonical_query_string(param),
                                       self.make_canonical_headers(param),
                                       self.make_signed_headers(),
                                       # self.signer.hashHex(param.get(GlacierParams.PAYLOAD).get_data()),

                                       # self.signer.hashHex(param.get_payload_content()),
                                       payload_hash,
        ]
        canonical_string = '\n'.join(canonical_request_content)
        logging.info('Canonical String\n%s\n', canonical_string)
        return canonical_string

    def make_signed_headers(self):
        """This lists the headers in the canonical_headers list,
        delimited with ";" and in alpha order.
        Note: The request can include any headers;
        canonical_headers and signed_headers lists those that you want to be included
        in the hash of the request. "Host" and "x-amz-date" are always required."""
        header_list = ['host', 'x-amz-date', 'x-amz-glacier-version']
        return ';'.join(sorted(header_list))

    def make_credential_scope(self, param):
        credential_scope = '/'.join([param.get(GlacierParams.DATE), self.region, settings.SERVICE, 'aws4_request'])
        return credential_scope

    def make_string_to_sign(self, param):
        string_to_sign = '\n'.join(
            [self.signer.algorithm, param.get(GlacierParams.AMZDATETIME), self.make_credential_scope(param),
             self.signer.hashHex(self.make_canonical_request(param).encode('utf-8'))])
        logging.info("String to sign: %s", string_to_sign)
        return string_to_sign

    def make_signature(self, param):
        signing_key = self.signer.getSignatureKey(param.get(GlacierParams.DATE), self.region, settings.SERVICE)
        # Sign the string_to_sign using the signing_key
        signature = self.signer.signHex(signing_key, self.make_string_to_sign(param))
        return signature

    def make_authorization_header(self, param):
        """The signing information can be either in a query string value or in a header named Authorization.
        Create authorization header and add to request headers"""
        authorization_header = self.signer.algorithm + ' ' + \
                               'Credential=' + self.signer.getAccessKey() + '/' + \
                               self.make_credential_scope(param) + ', ' + \
                               'SignedHeaders=' + self.make_signed_headers() + \
                               ', ' + 'Signature=' + self.make_signature(param)
        param.set_header('Authorization', authorization_header)
        # return authorization_header

    def list_vaults(self):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'GET')
        param.set(GlacierParams.URI, '/-/vaults')
        self.make_authorization_header(param)
        return self.perform_request(param)

    def initiate_multipart_upload(self, vault_name, multipard_desc, part_size=settings.DEFAULT_PART_SIZE):
        logging.info("Initiate for %s", multipard_desc)
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'POST')
        param.set(GlacierParams.URI, '/-/vaults/%s/multipart-uploads' % vault_name)
        param.set_header('x-amz-archive-description', multipard_desc)
        param.set_header('x-amz-part-size', str(part_size))
        self.make_authorization_header(param)
        return self.perform_request(param)

    def complete_multipart_upload(self, vault_name, upload_id, archive_size, archive_tree_hash):
        logging.info("Complete multipart for %s", upload_id)
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'POST')
        param.set(GlacierParams.URI, '/-/vaults/%s/multipart-uploads/%s' % (vault_name, upload_id))
        param.set_header('x-amz-archive-size', archive_size)
        # param.set_header('x-amz-sha256-tree-hash', archive_tree_hash)
        self.make_authorization_header(param)
        return self.perform_request(param)

    def upload_part(self, vault_name, upload_id, part_size, part_number, archive_path, archive_hash, part_tree_hash):
        logging.info("uploading part %i, file from position %i to %i", part_number, part_number * part_size, (part_number+1) * part_size )
        archive_size = os.path.getsize(archive_path)
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'PUT')
        param.set(GlacierParams.URI, '/-/vaults/%s/multipart-uploads/%s' % (vault_name, upload_id))
        payload = ChunkFileObject(file_path, 'rb', start = part_number * part_size, end = (part_number + 1) * part_size,
                                  callback = progress_bar("part %i" %part_number, part_number * part_size, min(archive_size, (part_number + 1) * part_size)))
        param.set(GlacierParams.PAYLOAD, payload)
        param.set_header('Content-Length', str(min(archive_size - part_number * part_size, part_size)))
        param.set_header('Content-Range', "bytes %s-%s/*"
                         % (part_number * part_size, min(archive_size, (part_number + 1) * part_size) - 1))
        # logging.debug('Content-Range:bytes %i-%i/*', part_number * part_size, min(archive_size, (part_number + 1) * part_size ) -1 )
        param.set_header('x-amz-content-sha256', self.signer.hashHex(param.get_payload_content()))
        param.set_header('x-amz-sha256-tree-hash', part_tree_hash)
        self.make_authorization_header(param)
        return self.perform_request(param)

    def multiupload_archive(self, vault_name, archive_path):
        # initiate multipart upload
        logging.info("multiupload_archive. Valut: %s Path: %s", vault_name, archive_path)
        init_resp = self.initiate_multipart_upload(vault_name, self.get_archive_name(archive_path))
        upload_id = init_resp.headers.get('x-amz-multipart-upload-id')
        logging.info("Upload ID received: %s" , upload_id)
        if not upload_id:
            logging.error("Invalid upload ID received: %s" , upload_id)
            raise InvalidIDException()
        # Setup tree hashes for archive parts
        archive_size = os.path.getsize(archive_path)
        part_size = settings.DEFAULT_PART_SIZE  # 256Mb
        part_bytes_tree_hashes = [None] * int(
            archive_size / part_size + min(1, archive_size % part_size))  # number of archive parts
        logging.debug("Archive size: %i - Part size: %i - # parts: %i", archive_size, part_size, len(part_bytes_tree_hashes))
        start_byte = 0
        part_number = 0
        while start_byte < archive_size:
            part_bytes_tree_hashes[part_number] = tree_hash(archive_path, start_byte, part_size)
            part_number += 1
            start_byte += part_size
        archive_tree_hash = bytes_to_hex(build_tree_from_root(part_bytes_tree_hashes)[-1][0])
        part_hex_tree_hashes = list(map(bytes_to_hex, part_bytes_tree_hashes))
        logging.debug("Archive hash: %s", archive_tree_hash)
        logging.debug("Parts hashes: \n%s", '\n'.join(part_hex_tree_hashes))
        # Upload parts
        for i in range(len(part_hex_tree_hashes)):
            part_resp = self.upload_part(vault_name, upload_id, part_size, i,
                                         archive_path, archive_tree_hash, part_hex_tree_hashes[i])
            logging.debug("Part %i response: %s", i, part_resp)
            if part_resp.status_code > 299:
                logging.debug("Stopping upload due to failed response for upload part %i", i)
                return None
        compl_resp = self.complete_multipart_upload(vault_name, upload_id, archive_size, archive_tree_hash)
        if not compl_resp or compl_resp.status_code > 299:
            logging.error("Error compliting upload multipart: %s" %compl_resp.text)
        logging.debug("Complete part response: %s", compl_resp)
        return compl_resp

    def upload_archive(self, vault_name, file_path):
        '''
        Upload a file in a single upload (not multipart)
        :param file_path: path of the file to upload
        :param vault_name: Vault name
        :return: The Requests response object
        '''
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'POST')
        param.set(GlacierParams.URI, '/-/vaults/%s/archives' % vault_name)
        param.set_header('Content-Length', str(os.path.getsize(file_path)))
        param.set_header('x-amz-archive-description', self.get_archive_name(file_path))
        content = ChunkFileObject(file_path, 'rb')
        param.set(GlacierParams.PAYLOAD, content)
        param.set_header('x-amz-content-sha256', self.signer.hashHex(param.get_payload_content()))
        param.set_header('x-amz-sha256-tree-hash', bytes_to_hex(tree_hash(file_path, 0, content.end)))
        self.make_authorization_header(param)
        return self.perform_request(param)

    def perform_request(self, param):
        method = param.get(GlacierParams.METHOD)
        request_headers = param.get(GlacierParams.HEADERS)
        endpoint = 'https://%s%s' % (self.host, param.get(GlacierParams.URI))
        request_url = endpoint + '?' + self.make_canonical_query_string(param)
        response = None
        # logging.info("%s %s", method, endpoint)
        if self.debug:
            print('Request URL = ' + request_url)
        # Perform request and get response
        try:
            if method == 'POST':
                payload = param.get(GlacierParams.PAYLOAD)
                if payload:
                    response = requests.post(request_url, headers=request_headers, data=payload)
                else:
                    response = requests.post(request_url, headers=request_headers)
            elif method == 'GET':
                response = requests.get(request_url, headers=request_headers)
            elif method == 'PUT':
                payload = param.get(GlacierParams.PAYLOAD)
                response = requests.put(request_url, headers=request_headers,
                                         data=payload)
                payload.close()
            elif method == 'DELETE':
                pass
            else:
                raise InvalidMethodException("Invalid method %s" % method)
        except:
            logging.fatal("Unable to perform request: %s" % sys.exc_info()[0])
            raise

        logging.debug("Response: %s", str(response))
        if response.status_code > 299: # Some error
            logging.error("Error in response: %s", response.text)
        # Log request / response
        try:
                if response.headers:
                    response.headers.setdefault('x_amzn_requestid', response.headers.get('x-amzn-RequestId', ''))
                    self.logger.log_response(response.headers, response.text, param)
                else:
                    logging.info("Empty header response")
        except:
            logging.error("Unable to log response: %s" % response)
        finally:
            self.logger.log_request(request_headers, param)
        return response

    def get_archive_name(self, file_path):
        """returns the archive name from the file path"""
        return os.path.basename(file_path)


class InvalidRegionException(Exception):
    pass


class InvalidMethodException(Exception):
    pass

class InvalidIDException(Exception):
    pass

if __name__ == '__main__':
    logging.basicConfig(filename='trace.log', format='%(asctime)s\t%(levelname)s\t%(funcName)s()\t%(message)s', level=logging.DEBUG)
    # logging.basicConfig(stream=sys.stdout, format='%(asctime)s\t%(levelname)s\t%(funcName)s()\t%(message)s', level=logging.DEBUG)
    logging.info('**** Starting new log ****')
    # logging.info('test')
    # logging.warning('test')
    c = GlacierClient('us-east-1', debug=False)
    file_path = "testupload-multi.txt"
    #print(c.multiupload_archive('Foto', file_path))
    # response = c.upload_archive('Foto', file_path)
    response = c.multiupload_archive('pyGlacier', file_path)
    # response = c.upload_archive('Foto', file_path)
    # response = c.list_vaults()
    # print(response.status_code)
    # print(response.text)
    # print(response.encoding)
    # print(response.headers)