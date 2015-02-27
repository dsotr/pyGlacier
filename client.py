# -*- coding: latin-1 -*-

import urllib.parse
import os
import sys
import requests
import settings
import logging
from settings import GlacierParams
import json

from aws_libs import Signer, ChunkReader, tree_hash, bytes_to_hex, build_tree_from_root, progress_bar
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
                                       self.signer.hashHex(param.get(GlacierParams.PAYLOAD).get_data()),
        ]
        if self.debug:
            print('Canonical String\n' + '\n'.join(canonical_request_content) + '\n******************')
        return '\n'.join(canonical_request_content)

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
        if self.debug:
            print("String to sign:")
            print(string_to_sign)
            print("******************")
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
        # param.make_dates()
        # endpoint = 'https://%s/-/vaults' % self.host
        # request_url = endpoint + '?' + self.make_canonical_query_string(param)
        self.make_authorization_header(param)

        # self.logger.log_request(param.get(GlacierParams.HEADERS))
        # r = requests.get(request_url, headers=param.get(GlacierParams.HEADERS))
        # self.logger.log_response(r.headers)
        return self.perform_request(param)

    def initiate_multipart_upload(self, vault_name, multipard_desc, part_size=settings.DEFAULT_PART_SIZE):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'POST')
        param.set(GlacierParams.URI, '/-/vaults/%s/multipart-uploads' % vault_name)
        param.set_header('x-amz-archive-description', multipard_desc)
        param.set_header('x-amz-part-size', str(part_size))
        self.make_authorization_header(param)
        return self.perform_request(param)

    def complete_multipart_upload(self, vault_name, upload_id, archive_size, archive_tree_hash):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'PUT')
        param.set(GlacierParams.URI, '/-/vaults/%s/multipart-uploads/%s' % (vault_name, upload_id))
        param.set_header('x-amz-archive-size', archive_size)
        param.set_header('x-amz-sha256-tree-hash​', archive_tree_hash)
        self.make_authorization_header(param)
        return self.perform_request(param)

    def upload_part(self, vault_name, upload_id, part_size, part_number, archive_path, archive_hash, part_tree_hash):
        logging.info("uploading part %i, file from position %i to %i", part_number, part_number * part_size, part_size)
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'PUT')
        param.set(GlacierParams.URI, '/-/vaults/%s/multipart-uploads/%s' % (vault_name, upload_id))
        g = ChunkReader(archive_path, part_number * part_size, part_size,
                        callback_function=progress_bar(
                            "File %s - chunk %i" % (os.path.basename(archive_path), part_number)))
        param.set(GlacierParams.PAYLOAD, g)
        archive_size = os.path.getsize(archive_path)
        param.set_header('Content-Length', str(min(archive_size - part_number * part_size, part_size)))
        param.set_header('Content-Range', "%s-%s/*"
                         % (part_number * part_size, min(archive_size, (part_number + 1) * part_size)))
        param.set_header('x-amz-content-sha256', archive_hash)
        # part_tree_hash = tree_hash(archive_path, part_number*part_size, part_size)
        param.set_header('x-amz-sha256-tree-hash', part_tree_hash)
        self.make_authorization_header(param)
        return self.perform_request(param)

    def multiupload_archive(self, vault_name, archive_path):
        # initiate multipart upload
        logging.warning("Hello world!")
        init_resp = self.initiate_multipart_upload(vault_name, self.get_archive_name(archive_path))
        upload_id = init_resp.headers.get('x-amz-multipart-upload-id')
        logging.info(upload_id)
        # print(init_resp.content.decode().replace('\\\\n', '\n'))
        # return init_resp
        # location = init_resp.headers.get('Location')
        # Setup tree hashes for archive parts
        archive_size = os.path.getsize(archive_path)
        part_size = settings.DEFAULT_PART_SIZE  # 256Mb
        start_byte = 0
        part_bytes_hashes = [None] * int(
            archive_size / part_size + min(1, archive_size % part_size))  # number of archive parts
        if self.debug:
            print("Archive size:%s\nPart size:%s\n# parts:%s\n******************"
                  % (archive_size, part_size, len(part_bytes_hashes)))
        part_number = 0
        while start_byte < archive_size:
            part_bytes_hashes[part_number] = tree_hash(archive_path, start_byte, part_size)
            part_number += 1
            start_byte += part_size
        archive_tree_hash = bytes_to_hex(build_tree_from_root(part_bytes_hashes)[-1][0])
        part_hex_hashes = list(map(bytes_to_hex, part_bytes_hashes))
        if self.debug:
            print("Hash calculation complete.")
            print("Archive hash: %s" % archive_tree_hash)
            print("Parts hashes: \n%s" % '\n'.join(part_hex_hashes))
        for i in range(len(part_hex_hashes)):
            part_resp = self.upload_part(vault_name, upload_id, part_size, i,
                                         archive_path, archive_tree_hash, part_hex_hashes[i])
            if self.debug:
                print(part_resp)
        compl_resp = self.complete_multipart_upload(vault_name, upload_id, archive_size, archive_tree_hash)
        if self.debug:
            print(compl_resp)
        return compl_resp

    def upload_archive(self, file_path, vault_name):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'POST')
        param.set(GlacierParams.URI, '/-/vaults/%s/archives' % vault_name)
        # param.make_dates()
        param.set_header('Content-Length', str(os.path.getsize(file_path)))
        param.set_header('x-amz-archive-description', self.get_archive_name(file_path))
        content = ChunkReader(file_path, 0, os.path.getsize(file_path), os.path.getsize(file_path))
        param.set(GlacierParams.PAYLOAD, content)
        param.set_header('x-amz-content-sha256', self.signer.hashHex(content.get_data()))
        # endpoint = 'https://%s%s' % (self.host, param.get(GlacierParams.URI))
        # request_url = endpoint + '?' + self.make_canonical_query_string(param)
        # self.make_authorization_header(param)
        # if self.debug:
        # print('Request URL = ' + request_url)
        # r = requests.post(request_url, headers=param.get(GlacierParams.HEADERS), data=content)
        # print('Response code: %d\n' % r.status_code)
        return self.perform_request(param)

    def perform_request(self, param):
        method = param.get(GlacierParams.METHOD)
        request_headers = param.get(GlacierParams.HEADERS)
        endpoint = 'https://%s%s' % (self.host, param.get(GlacierParams.URI))
        request_url = endpoint + '?' + self.make_canonical_query_string(param)
        response = None
        logging.info("Perform request %s %s", method, endpoint)
        if self.debug:
            print('Request URL = ' + request_url)
        # Perform request and get response
        try:
            if method == 'POST':
                response = requests.post(request_url, headers=request_headers,
                                         data=param.get(GlacierParams.PAYLOAD).get_chunk_generator())
            elif method == 'GET':
                response = requests.get(request_url, headers=request_headers)
            elif method == 'PUT':
                print("Performing PUT")
                response = requests.put(request_url, headers=request_headers,
                                         data=param.get(GlacierParams.PAYLOAD).get_data())
            elif method == 'DELETE':
                pass
            else:
                raise InvalidMethodException("Invalid method %s" % method)
        except:
            sys.stderr.write("Unable to perform request\n")
            response = None
        logging.debug("Response: %s", str(response))
        # Log request / response
        try:
                if response.headers:
                    # request_headers.setdefault('x_amzn_requestid', response.headers.get('x-amzn-RequestId', ''))
                    response.headers.setdefault('x_amzn_requestid', response.headers.get('x-amzn-RequestId', ''))
                    self.logger.log_response(response.headers, response.text, param)
                    logging.info("Logged response")
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


if __name__ == '__main__':
    logging.basicConfig(filename='example.log', format='%(asctime)s\t%(levelname)s\t%(funcName)s()\t%(message)s', level=logging.DEBUG)
    logging.info('**** Starting new log ****')
    # logging.info('test')
    # logging.warning('test')
    c = GlacierClient('us-east-1', debug=False)
    file_path = "Downloads.tar"
    #print(c.multiupload_archive('Foto', file_path))
    # response = c.initiate_multipart_upload('test-multipart-1','Foto')
    # response = c.list_vaults()
    # print(response.status_code)
    # print(response.text)
    # print(response.encoding)
    # print(response.headers)