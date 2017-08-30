from cream import ERS
import json

from unittest import TestCase
from unittest.mock import patch, Mock

class ErsTest(TestCase):

    def setUp(self):
        self.ise = ERS('ise_node', 'ers_user', 'ers_pass')

    def test_mac_test(self):
        result = self.ise._mac_test('24:be:05:0b:01:ab')

        self.assertTrue(result)

    @patch('cream.ERS')
    def test_get_endpoint_groups(self, MockERS):
        ise = MockERS('ise_node', 'ers_user', 'ers_pass')

        ise.get_endpoint_groups.return_value = {
            'SearchResult': {
                'total': 12,
                'resources': [
                    {
                        'id': '3b0882f0-f42f-11e2-bd54-005056bf2f0a',
                        'name': 'Cisco-IP-Phone',
                        'description': 'Identity Group for Profile: Cisco-IP-Phone',
                        'link': {
                            'rel': 'self',
                            'href': 'https://10.8.2.61:9060/ers/config/endpointgroup/3b0882f0-f42f-11e2-bd54-005056bf2f0a',
                            'type': 'application/xml'
                        }
                    }
                ]
            }
        }

        response = ise.get_endpoint_groups()
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)
        assert MockERS.called




if __name__ == '__main__':
    unittest.main()
