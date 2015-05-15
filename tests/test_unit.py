# -*- coding: latin-1 -*-

from client import GlacierClient
from unittest import TestCase
import requests
import re
from aws_libs import *
from subprocess import Popen, PIPE

class TestInstantiateLogging(TestCase):
    def test_logging(self):
        logging.basicConfig(filename='trace.log', format='%(asctime)s\t%(levelname)s\t[%(module)s]\t%(funcName)s()\t%(message)s', level=logging.DEBUG)
        print('PASSED: Logging on')

class TestTree_hash(TestCase):
    def test_tree_hash(self):
        file_path = "testupload.txt"
        out_j = Popen(['java', 'TreeHashExample', file_path], stdout=PIPE)
        out_p = tree_hash(file_path, 0, os.path.getsize(file_path))
        self.assertEqual(out_j.stdout.read().decode(), bytes_to_hex(out_p))
        print("PASSED: tree hash")
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
        url = 'http://checkip.dns.he.net/'
        reg = '<body>.*?([0-9.]+).*</body>'
        r = requests.get(url)
        m = re.findall(reg, r.text, re.DOTALL)
        self.assertTrue(len(r.content) > 88)
        print("PASSED test_download_data(): %s" % m[0].strip())