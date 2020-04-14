
[![Python 3](https://pyup.io/repos/github/falkowich/ise/python-3-shield.svg)](https://pyup.io/repos/github/falkowich/ise/) [![Updates](https://pyup.io/repos/github/falkowich/ise/shield.svg)](https://pyup.io/repos/github/falkowich/ise/) [![Known Vulnerabilities](https://snyk.io/test/github/falkowich/ise/badge.svg?style=plastic)](https://snyk.io/test/github/falkowich/ise) [![Maintainability](https://api.codeclimate.com/v1/badges/b377fd23b5de7444c258/maintainability)](https://codeclimate.com/github/falkowich/ise/maintainability) ![Publish PyPI and TestPyPI](https://github.com/falkowich/ise/workflows/Publish%20ise%20to%20PyPI%20and%20TestPyPI%20%F0%9F%93%A6/badge.svg)

# ISE

Python module to manage Cisco ISE via the REST API.

## History

All initial work is done by [https://github.com/bobthebutcher](https://github.com/bobthebutcher) and [https://github.com/mpenning](https://github.com/mpenning.).  
I forked from them and updated so it worked with ISE 2.2.x and changed all functions to json calls.  

* Merged back from the work that [https://github.com/karrots](https://github.com/karrots) has done efter I paused the updates.  
* Converted to pipenv packages instead of requirements.txt
* Updated to ISE 2.4.x
* Merged back from the work that [https://github.com/msom](https://github.com/msom) has done with some good device fixes.
  * *One big thing is that module is now renamed from ise.cream to just ise.*
* First publish to PyPi with the help of [https://github.com/JonasKs](https://github.com/JonasKs).

## Status

Tested and used in our environment at work. But as usual it's up to you to test this out in a test environment so everything works as intended.

Is you have any suggestions or find a bug, create a issue and I'll try to fix it :)

## Testing

Testing has been completed on ISE v2.4.0.357 and with python 3.7.3  
Until a mock of ERS-API is done, a simple test is in test/test_ers.py  
To run tests:

* make a copy of config-DEFAULT.py to config.py
* edit uri with settings to your test ise
* run python test-ers.py

### Enable REST API

[http://www.cisco.com/c/en/us/td/docs/security/ise/2-0/api_ref_guide/api_ref_book/ise_api_ref_ers1.html#pgfId-1079790](http://www.cisco.com/c/en/us/td/docs/security/ise/2-0/api_ref_guide/api_ref_book/ise_api_ref_ers1.html#pgfId-1079790)
Need to add an ISE Administrator with the "ERS-Admin" or "ERS-Operator" group assignment is required to use the API.

### Installation

#### From PyPi

```bash
pip install ISE
```

#### From Repository

```bash
mkdir path/to/ise
cd path/to/ise
git clone https://github.com/falkowich/ise.git
```

##### Add to path

```python
import sys
sys.path.append('/path/to/ise/')
```

### Usage

```python
from ise import ERS
ise = ERS(ise_node='192.168.0.10', ers_user='ers', ers_pass='supersecret', verify=False, disable_warnings=True)
```

#### Methods return a result dictionary

```python
{
    'success': True/False,
    'response': 'Response from request',
    'error': 'Error if any',
}
```

#### Get a list of identity groups

```python
ise.get_identity_groups()['response']

[('NetworkAdmin',
  '5f0b74f0-14e9-11e5-a7a6-00505683258b',
  'Group for Network Admins with CLI access to network equipment'),
 ('OWN_ACCOUNTS (default)',
  'cecdab40-8d30-11e5-82ce-005056834dc2',
  'Default OWN_ACCOUNTS (default) User Group'),
 ('GuestType_Contractor (default)',
  'c9b6b890-8d30-11e5-82ce-005056834dc2',
  'Identity group mirroring the guest type '),
 ...]
```

#### Get details about an identity group

```python
ise.get_identity_group(group='Employee')['response']

{'description': 'Default Employee User Group',
 'id': 'f80e5ce0-f42e-11e2-bd54-005056bf2f0a',
 'link': {'href': 'https://10.8.2.61:9060/ers/config/identitygroup/f80e5ce0-f42e-11e2-bd54-005056bf2f0a',
          'rel': 'self',
          'type': 'application/xml'},
 'name': 'Employee',
 'parent': 'NAC Group:NAC:IdentityGroups:User Identity Groups'}

```

#### Get details about an endpoint

```python
ise.get_endpoint_group(group='Resurs')['response']

 {'description': '',
 'id': 'bf6bdcf0-14ed-11e5-a7a6-00505683258b',
 'link': {'href': 'https://10.8.2.61:9060/ers/config/endpointgroup/bf6bdcf0-14ed-11e5-a7a6-00505683258b',
          'rel': 'self',
          'type': 'application/xml'},
 'name': 'Resurs',
 'systemDefined': False}

```

#### Get endpoint identity groups

```python
ise.get_endpoint_groups()['response']

  [('Cisco-IP-Phone',
    '265079a0-6d8e-11e5-978e-005056bf2f0a',
    'Identity Group for Profile: Cisco-IP-Phone'),
   ('Resurs', '32c8eb40-6d8e-11e5-978e-005056bf2f0a', ''),
   ...]

```

#### Add endpoint

```python
ise.add_endpoint(name='test02', mac='AA:BB:CC:00:11:24', group_id='bf6bdcf0-14ed-11e5-a7a6-00505683258b', description='test02')
{'response': 'test02 Added Successfully', 'success': True, 'error': ''}
```

#### Delete endpoint

```python
ise.delete_endpoint(mac='AA:BB:CC:00:11:27')
{'error': '', 'response': 'AA:BB:CC:00:11:27 Deleted Successfully', 'success': True}

```

#### Get a list of internal users

```python
ise.get_users()['response']

[('test01', '85fd1eb0-c6fa-11e5-b6b6-000c297b78b4'),
 ('test02', '54fd1eb0-c5fb-54e5-b6b6-00204597b28b1'),
 ...]

```

#### Get details about an internal user

```python
ise.get_user(user_id='test02')['response']

{'changePassword': False,
 'customAttributes': {},
 'enablePassword': '*******',
 'enabled': True,
 'expiryDateEnabled': False,
 'id': '54fd1eb0-c5fb-54e5-b6b6-00204597b28b1',
 'identityGroups': '5f0b74f0-14e9-11e5-a7a6-00505683258b',
 'link': {'href': 'https://10.8.2.61:9060/ers/config/internaluser/a837bd55-f2b7-41e3-b0ff-c5ddf9af398c',
          'rel': 'self',
          'type': 'application/xml'},
 'name': 'test02',
 'password': '*******',
 'passwordIDStore': 'Internal Users'}

```

#### Add an internal user

```python
ise.add_user(user_id='test11', password='TeStInG11', user_group_oid='5f0b74f0-14e9-11e5-a7a6-00505683258b')

{'error': '', 'response': 'test11 Added Successfully', 'success': True}

```

#### Delete an internal user

```python
ise.delete_user(user_id='test11')

{'error': '', 'response': 'test11 Deleted Successfully', 'success': True}

```

#### Get a list of devices

```python
ise.get_devices()['response']

[('TestDevice01', '6680f410-5277-11e5-9a52-05505683258b'),
 ('TestDevice02', '64d9b32-5c56-11e5-9a52-00502683258b'),
 ...]

```

#### Get details about a device

```python
ise.get_device(device='TestDevice02')['response']

{'NetworkDeviceGroupList': ['Stage#Stage',
                            'Device Type#All Device Types#Linux',
                            'Location#All Locations'],
 'NetworkDeviceIPList': [{'ipaddress': '10.8.1.55', 'mask': 32}],
 'authenticationSettings': {'enableKeyWrap': False,
                            'keyInputFormat': 'ASCII',
                            'networkProtocol': 'RADIUS',
                            'radiusSharedSecret': '******'},
 'coaPort': 0,
 'id': '74d9b830-5c76-11e5-9a52-00505683258b',
 'link': {'href': 'https://10.8.2.61:9060/ers/config/networkdevice/74d9b830-5c76-11e5-9a52-00505683258b',
          'rel': 'self',
          'type': 'application/xml'},
 'modelName': 'Linux',
 'name': 'TestDevice02',
 'profileName': 'Cisco'}

```

#### Get a list of device groups

```python
ise.get_device_groups()['response']

[('Device Type#All Device Types', '526240e0-f42e-11e2-bd54-005056bf2f0a'),
 ('Device Type#All Device Types#Switch', 'e25bd190-14e6-11e5-a7a6-00505683258b'),
 ('Device Type#All Device Types#Wism', 'e6b085b0-14e6-11e5-a7a6-00505683258b'),
 ('IPSEC#Is IPSEC Device', '0d3f19b0-30c1-11e7-88b5-005056834dc2'),
 ('IPSEC#Is IPSEC Device#No', '0dac0c50-30c1-11e7-88b5-005056834dc2'),
 ('IPSEC#Is IPSEC Device#Yes', '0d74f6c0-30c1-11e7-88b5-005056834dc2'),
 ('Location#All Locations', '522b7970-f42e-11e2-bd54-005056bf2f0a'),
 ...]

```

#### Add a device

```python
ise.add_device(name='testdevice03',
               ip_address='192.168.10.10',
               radius_key='foo',
               snmp_ro='bar',
               dev_group='Stage#Stage#Closed',
               dev_location='Location#All Locations#Site21',
               dev_type='Device Type#All Device Types#Switch')

{'error': '', 'response': 'testdevice03 Added Successfully', 'success': True}

```

#### Delete a device

```python
ise.delete_device(device='testdevice03')

{'error': '', 'response': 'testdevice03 Deleted Successfully', 'success': True}
```
