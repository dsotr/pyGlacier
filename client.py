# -*- coding: latin-1 -*-

import urllib.parse
import os
import sys
import requests
import settings
import logging.config
from settings import GlacierParams
import json
from aws_libs import Signer, tree_hash, bytes_to_hex, build_tree_from_root, progress_bar, ChunkFileObject
from dblogger import DBLogger


class GlacierClient:
    def __init__(self, region='us-east-1'):
        self.logger = logging.getLogger('[GlacierClient]')
        self.signer = Signer()
        self.database = DBLogger('database.db')
        if region in settings.REGIONS:
            self.region = region
        else:
            raise ValueError('Invalid region %s.\nAvailable regions: %s' % (region, str(settings.REGIONS)))
        self.host = 'glacier.%s.amazonaws.com' % self.region
        self.payload = ''

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
        self.logger.debug('Canonical header: %s' % canonical_header)
        return canonical_header

    def make_canonical_request(self, param):
        if param.get_canonical_string_hash():
            payload_hash = param.get_canonical_string_hash()
        else:
            payload_hash = self.signer.hashHex(param.get_payload_content())
        canonical_request_content = [param.get(GlacierParams.METHOD),
                                     param.get(GlacierParams.URI),
                                     self.make_canonical_query_string(param),
                                     self.make_canonical_headers(param),
                                     self.make_signed_headers(),
                                     payload_hash,
                                     ]
        canonical_string = '\n'.join(canonical_request_content)
        self.logger.debug('Canonical String\n%s\n', canonical_string)
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
        self.logger.debug("String to sign: %s", string_to_sign)
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
        vault_resp = self.perform_request(param)
        self.logger.info("Vaults list: %s", vault_resp.text)
        return vault_resp

    def describe_vault(self, vault):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'GET')
        param.set(GlacierParams.URI, '/-/vaults/%s' % vault)
        self.make_authorization_header(param)
        vault_resp = self.perform_request(param)
        self.logger.info("Vault %s content: %s", vault, vault_resp.text)
        return vault_resp

    def initiate_multipart_upload(self, vault_name, multipard_desc, part_size=settings.DEFAULT_PART_SIZE):
        self.logger.info("Initiate multipart upload for %s", multipard_desc)
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'POST')
        param.set(GlacierParams.URI, '/-/vaults/%s/multipart-uploads' % vault_name)
        param.set_header('x-amz-archive-description', multipard_desc)
        param.set_header('x-amz-part-size', str(part_size))
        self.make_authorization_header(param)
        return self.perform_request(param)

    def complete_multipart_upload(self, vault_name, upload_id, archive_size, archive_tree_hash):
        self.logger.info("Complete multipart for %s", upload_id)
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'POST')
        param.set(GlacierParams.URI, '/-/vaults/%s/multipart-uploads/%s' % (vault_name, upload_id))
        param.set_header('x-amz-archive-size', archive_size)
        param.set_header('x-amz-sha256-tree-hash', archive_tree_hash)
        self.make_authorization_header(param)
        return self.perform_request(param)

    def upload_part(self, vault_name, upload_id, part_size, part_number, archive_path, archive_hash, part_tree_hash):
        self.logger.info("uploading part %i, file from position %i to %i", part_number, part_number * part_size,
                         (part_number + 1) * part_size)
        archive_size = os.path.getsize(archive_path)
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'PUT')
        param.set(GlacierParams.URI, '/-/vaults/%s/multipart-uploads/%s' % (vault_name, upload_id))
        payload = ChunkFileObject(archive_path, 'rb', start=part_number * part_size, end=(part_number + 1) * part_size,
                                  callback=progress_bar("part %i" % part_number, part_number * part_size,
                                                        min(archive_size, (part_number + 1) * part_size) - 1))
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
        self.logger.info("multiupload_archive. Valut: %s Archive: %s", vault_name, archive_path)
        init_resp = self.initiate_multipart_upload(vault_name, self.get_archive_name(archive_path))
        upload_id = init_resp.headers.get('x-amz-multipart-upload-id')
        self.logger.info("Upload ID received: %s", upload_id)
        if not upload_id:
            self.logger.error("Invalid upload ID received: %s", upload_id)
            raise ValueError("Invalid upload ID received: %s" % upload_id)
        # Setup tree hashes for archive parts
        archive_size = os.path.getsize(archive_path)
        self.logger.info("Archive size: %i", archive_size)
        part_size = settings.DEFAULT_PART_SIZE  # 256Mb
        part_bytes_tree_hashes = [None] * int(
            archive_size / part_size + min(1, archive_size % part_size))  # number of archive parts
        self.logger.debug("Part size: %i - # parts: %i", part_size, len(part_bytes_tree_hashes))
        start_byte = 0
        part_number = 0
        while start_byte < archive_size:
            self.logger.info("Hashing part %i", part_number)
            part_bytes_tree_hashes[part_number] = tree_hash(archive_path, start_byte, part_size)
            part_number += 1
            start_byte += part_size
        archive_tree_hash = bytes_to_hex(build_tree_from_root(part_bytes_tree_hashes)[-1][0])
        part_hex_tree_hashes = list(map(bytes_to_hex, part_bytes_tree_hashes))
        self.logger.debug("Archive hash: %s", archive_tree_hash)
        self.logger.debug("Parts hashes: \n%s", '\n'.join(part_hex_tree_hashes))
        # Upload parts
        for i in range(len(part_hex_tree_hashes)):
            part_resp = self.upload_part(vault_name, upload_id, part_size, i,
                                         archive_path, archive_tree_hash, part_hex_tree_hashes[i])
            self.logger.debug("Part %i response: %s", i, part_resp)
            if part_resp.status_code > 299:
                self.logger.error("Stopping upload due to failed response for upload part %: %s", i, part_resp.text)
                return None
        compl_resp = self.complete_multipart_upload(vault_name, upload_id, archive_size, archive_tree_hash)
        if not compl_resp or compl_resp.status_code > 299:
            self.logger.error("Error compliting upload multipart: %s", compl_resp.text)
        self.logger.info("Complete part response: %s", compl_resp.text)
        return compl_resp

    def list_multuploads(self, vault_name):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'GET')
        param.set(GlacierParams.URI, '/-/vaults/%s/multipart-uploads' % vault_name)
        self.make_authorization_header(param)
        list_resp = self.perform_request(param)
        self.logger.info("Multiupload list: %s", list_resp.text)
        return list_resp

    def abort_multiupload(self, vault_name, upload_id):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'DELETE')
        param.set(GlacierParams.URI, '/-/vaults/%s/multipart-uploads/%s' % (vault_name, upload_id))
        self.make_authorization_header(param)
        resp = self.perform_request(param)
        self.logger.info("Archive delete result: %s", resp.status_code)
        return resp

    def list_jobs(self, vault_name):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'GET')
        param.set(GlacierParams.URI, '/-/vaults/%s/jobs' %vault_name)
        self.make_authorization_header(param)
        resp = self.perform_request(param)
        self.logger.info("Vault %s jobs: %s", vault_name, resp.text)
        return resp

    def describe_job(self, vault_name, job_id):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'GET')
        param.set(GlacierParams.URI, '/-/vaults/%s/jobs/%s' %(vault_name,job_id))
        self.make_authorization_header(param)
        resp = self.perform_request(param)
        self.logger.info("Job %s description: %s", job_id, resp.text)
        return resp

    def initiate_job(self, vault_name, json_body: dict):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'POST')
        param.set(GlacierParams.URI, '/-/vaults/%s/jobs' %vault_name)
        param.set(GlacierParams.PAYLOAD, json_body)
        self.make_authorization_header(param)
        resp = self.perform_request(param)
        self.logger.info("Job initiation: %s", resp.text)
        return resp

    def initiate_inventory_job(self, vault_name):
        """
        Inventory request. It doesn't use start-end dates, nor limits or markers.
        :param vault_name: Vault name for the inventory request
        :return: the id of the job or None
        """
        body = {
            "Type": "inventory-retrieval",
            "Description": "pyGlacier inventory retrieval",
            "Format": "JSON",
            # "SNSTopic": String,
            # "InventoryRetrievalParameters": {
                # "StartDate": String,
                # "EndDate": String,
                # "Limit": String,
                # "Marker": String
            # }
        }
        json_body = json.dumps(body)
        resp = self.initiate_job(vault_name, json_body)
        if resp:
            return resp.headers.get("x-amz-job-id", None)

    def get_archive_job(self):
        # TODO: implement method
        pass

    def get_job_output(self, vault_name, job_id):
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'GET')
        param.set(GlacierParams.URI, '/-/vaults/%s/jobs/%s/output' %(vault_name, job_id))
        self.make_authorization_header(param)
        resp = self.perform_request(param)
        if resp and resp.status_code == 200:
            self.logger.info("Job output received")
        return resp

    def upload_archive(self, vault_name, file_path):
        """
        Upload a file in a single upload (not multipart)
        :param file_path: path of the file to upload
        :param vault_name: Vault name
        :return: The Requests response object
        """
        param = GlacierParams()
        param.set(GlacierParams.METHOD, 'POST')
        param.set(GlacierParams.URI, '/-/vaults/%s/archives' % vault_name)
        param.set_header('Content-Length', str(os.path.getsize(file_path)))
        param.set_header('x-amz-archive-description', self.get_archive_name(file_path))
        self.logger.info("Archive description: %s", self.get_archive_name(file_path))
        content = ChunkFileObject(file_path, 'rb', callback=progress_bar("Upload archive", 0, os.path.getsize(file_path) - 1))
        param.set(GlacierParams.PAYLOAD, content)
        self.logger.info("Hashing archive %s", file_path)
        param.set_header('x-amz-content-sha256', self.signer.hashHex(param.get_payload_content()))
        param.set_header('x-amz-sha256-tree-hash', bytes_to_hex(tree_hash(file_path, 0, content.end)))
        self.make_authorization_header(param)
        self.logger.info("Uploading archive %s", file_path)
        upload_resp = self.perform_request(param)
        if not upload_resp:
            self.logger.error("Error compliting upload multipart: No response received")
        if upload_resp.status_code > 299:
            self.logger.error("Error compliting upload multipart: %s", upload_resp.text)
        self.logger.info("Complete part response: %s", upload_resp.text)
        return upload_resp

    def perform_request(self, param):
        method = param.get(GlacierParams.METHOD)
        request_headers = param.get(GlacierParams.HEADERS)
        endpoint = 'https://%s%s' % (self.host, param.get(GlacierParams.URI))
        request_url = endpoint + '?' + self.make_canonical_query_string(param)
        response = None
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
                response = requests.delete(request_url, headers=request_headers)
            else:
                raise ValueError("Invalid method %s for class requests" % method)
        except:
            self.logger.error("Unable to perform request: %s" % sys.exc_info()[0])
            raise
        if response:
            self.logger.debug("Response: %s", response.text)
            if response.status_code > 299:  # Some error
                self.logger.error("Error in response: %s", response.text)
        else:
            self.logger.error("No response received: %s", response)

        # Log request / response
        try:
            if response.headers:
                response.headers.setdefault('x_amzn_requestid', response.headers.get('x-amzn-RequestId', ''))
                self.database.insert_response(response.headers, response.text, param)
            else:
                self.logger.info("Empty header response")
        except:
            self.logger.error("Unable to log response: %s" % response)
        finally:
            self.database.insert_request(request_headers, param)
        return response

    def get_archive_name(self, file_path):
        """returns the archive name from the file path"""
        return os.path.basename(file_path)


if __name__ == '__main__':
    # logging.basicConfig(filename='trace.log', format='%(asctime)s\t%(levelname)s\t%(funcName)s()\t%(message)s', level=logging.DEBUG)
    # logging.basicConfig(stream=sys.stdout, format='%(asctime)s\t%(levelname)s\t%(funcName)s()\t%(message)s', level=logging.DEBUG)
    # logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    log_path = 'config/logging.json'
    with open(log_path, 'rt') as f:
        config = json.load(f)
    logging.config.dictConfig(config)
    c = GlacierClient('us-east-1')
    # c.list_vaults()
    # sys.exit(0)
    if len(sys.argv) > 2:
        c.upload_archive(sys.argv[1], sys.argv[2])
    else:
        print("Usage: %s <vault_name> <archive_name>" %sys.argv[0])
    #     print(sys.argv)
    #     c.multiupload_archive('Foto',sys.argv[1])
    #     sys.exit(0)
    # while True:
    #     cmd = input("Enter upload path[default tests/test.txt]:")
    #     if cmd=='exit':
    #         break
    #     cmd = cmd or 'tests/test.txt'
    #     archive_path = os.path.abspath(cmd)
    #     yn = input("Upload %s [y/n]?" %archive_path)
    #     if yn == 'y':
    #         response = c.multiupload_archive('pyGlacier', archive_path)
    #         print(response.text)

    # file_path = "tests/testupload-multi.txt"
    # print(c.multiupload_archive('Foto', file_path))
    # response = c.upload_archive('Foto', file_path)
    # response = c.upload_archive('Foto', file_path)
    # response = c.list_vaults()
    # print(response.status_code)
    # print(response.text)
    # print(response.encoding)
    # print(response.headers)
