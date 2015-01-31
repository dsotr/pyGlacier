from unittest import TestCase
from client import GlacierClient

__author__ = 'dani'


class TestGlacierClient(TestCase):
    def test_multiupload_archive(self):
        c = GlacierClient()
        response = c.multiupload_archive('Foto', 'test-upload.txt')
        self.assertIn('x-amz-multipart-upload-id', response.headers)
        self.assertIn('Location', response.headers)
        print(response.headers)
        # self.fail()