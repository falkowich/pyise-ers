# python -m unittest discover -s ../test
from cream import ERS
import json

import unittest
from unittest import TestCase
from unittest.mock import patch, Mock


class ErsTest(TestCase):

    def setUp(self):
        self.ise = ERS('ise_node', 'ers_user', 'ers_pass')

    def test_mac_test(self):
        result = self.ise._mac_test('24:be:05:0b:01:ab')

        self.assertTrue(result)

    def test_pass_ersresponse_error(self):
        result = self.ise._pass_ersresponse()

        self.asertTrue(result['error'])

    def test_pass_ersresponse_response(self):
        result = self.ise._pass_ersresponse()

        self.asertTrue(result['response'])


if __name__ == '__main__':
    unittest.main()
