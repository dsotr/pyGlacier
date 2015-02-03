from unittest import TestCase
from aws_libs import *
from subprocess import Popen, PIPE

__author__ = 'daniele.conca'


class TestTree_hash(TestCase):
    def test_tree_hash(self):
        file_path = "C:\\Users\\daniele.conca\\Downloads\\msf-v10-txt.axx"
        out_j = Popen(['java', 'TreeHashExample', file_path], stdout=PIPE)
        out_p = tree_hash(file_path, 0, os.path.getsize(file_path))
        self.assertEqual(out_j.stdout.read().decode(), out_p)