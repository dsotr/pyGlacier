# -*- coding: latin-1 -*-

from client import GlacierClient
from unittest import TestCase
import requests
from aws_libs import *
from subprocess import Popen, PIPE


# class TestTree_hash(TestCase):
#     def test_tree_hash(self):
#         # file_path = "Downloads.tar"
#         # out_j = Popen(['java', 'TreeHashExample', file_path], stdout=PIPE)
#         # out_p = tree_hash(file_path, 0, os.path.getsize(file_path))
#         # self.assertEqual(out_j.stdout.read().decode(), bytes_to_hex(out_p))
#         print("PASSED: tree hash")
#
# class TestGlacierClient(TestCase):
#     def test_multiupload_archive(self):
#         c = GlacierClient(debug=True)
#         file_path = "testupload.txt"
#         response = c.multiupload_archive('Foto', file_path)
#         self.assertIsNotNone(response)
#         self.assertIn('x-amz-multipart-upload-id', response.headers)
#         self.assertIn('Location', response.headers)
#         print("PASSED: Multiupload archive")
#
class TestConnection(TestCase):
    def test_download_data(self):
        url = 'http://checkip.dyndns.com/'
        r = requests.get(url)
        self.assertIsNotNone(r)
        self.assertTrue(len(r.content) > 88)
        print("PASSED test_download_data(): %s" % r.content[56:89].decode())