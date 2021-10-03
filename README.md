
[![Known Vulnerabilities](https://snyk.io/test/github/falkowich/pyise-ers/badge.svg)](https://snyk.io/test/github/falkowich/pyise-ers) [![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/falkowich/ise) ![Discord](https://img.shields.io/discord/858319928703975454?logo=discord) [![CodeQL](https://github.com/falkowich/pyise-ers/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/falkowich/pyise-ers/actions/workflows/codeql-analysis.yml)

# ISE-ERS API Wrapper

Python module to manage Cisco ISE via the REST API.  

## Namechange information

### After 0.2.0 information

In 2021 I tried to publish the library to DevNet and beq modulename was just "ise" I had to do a rename on the package, module and repository.  

* Repository is named pyise-ers,
* The PyPI package is namde pyise-ers.
* The module is named pyiseers (for conveniens of imports wihtout dashes in them)

If you use the "old 0.1.2.x" ise packages in PyPi, please update your requirements to pyise-ers to get continued updates.
(after testing everything in your environment offcourse)

## History

All initial work is done by [https://github.com/bobthebutcher](https://github.com/bobthebutcher) and [https://github.com/mpenning](https://github.com/mpenning.).  
I forked from them and updated so it worked with ISE 2.2.x and changed all functions to json calls.  

* 2021-10-01 » All history before 0.2 and the namechange to pyiseers is located [here](#History-before-0.2)
* 2021-10-01 » Deforked from upstream for simpler handling of PR's as of this [discusson](https://github.com/falkowich/ise/discussions/161)
* 2021-10-02 » Started work with namechange as of this [issue](https://github.com/falkowich/ise/issues/164) to pyise-ers
* 2021-10-03 » Pushed pyise-ers 0.2.0-rc to test.pypi.com
  
## Status

Tested and used in our environment at work. But as usual it's up to you to test this out in a test environment so everything works as intended.
If you have any suggestions or find a bug, create a issue and we will try to fix it :)

Feel free to [Join Discord Server](https://discord.gg/CA6FphRgF4) and contact me there too.
I moved away from slack to Discord to try it out when 0.2.0 will be released.

## Testing

These versions has been tested with pytest.

|pyise-ers|ise|ise patch|python|date|status|
|---|---|---|---|---|---|
|0.1.1|2.4.0.357|none|3.7.3|2019|depricated|
|0.1.2|2.7.0.356|11|3.7.7|2020|depricated|
|0.1.2|2.7.0.356|1|3.7.7|2020|depricated|
|0.2.0|2.7.0.356|none|3.7.12|2021-10-02|active|
|0.2.0|3.0.0.458|none|3.7.12|2021-10-02|active|

There are two tests available in tests/ directory.

### Manual test

To run the "manual" tests:

* make a copy of config-DEFAULT.py to config.py
* edit uri_27 and/or uri_30 with settings to your test ise server
* run python manual_test_ers.py

### Pytest

To run the testfiles with pytest-recording.  
The first time this is runned the directory `cassettes/` are created with saved .yaml files from the test.
That is so that the tests can be repeated without contacting ISE everytime.

* make a copy of config-DEFAULT.py to config.py
  * edit uri with settings to your test ise instance.
  * in the config.py there are a list where you can set multiple versions if ise instances.
* to run the tests
  * pytest --record-mode=rewrite (To rewrite cassettes with live data)
  * pytest (to reuse the recorded cassetes)

The plan is to extend the testing with testcoverage on this library.

### Enable REST API

[http://www.cisco.com/c/en/us/td/docs/security/ise/2-0/api_ref_guide/api_ref_book/ise_api_ref_ers1.html#pgfId-1079790](http://www.cisco.com/c/en/us/td/docs/security/ise/2-0/api_ref_guide/api_ref_book/ise_api_ref_ers1.html#pgfId-1079790)
Need to add an ISE Administrator with the "ERS-Admin" or "ERS-Operator" group assignment is required to use the API.

### Installation

#### From PyPi

```bash
pip install pyise-ers
```

#### From Repository

```bash
mkdir path/to/parent
cd path/to/parent
git clone https://github.com/falkowich/pyise-ers.git
```

##### Add to path

```python
import sys
sys.path.append('/path/to/parent/pyise-ers/')
```

### Usage

```python
from pyiseers import ERS
ise = ERS(ise_node='192.168.0.10', ers_user='ers', ers_pass='supersecret', verify=False, disable_warnings=True)
```

If ISE is configured to require CSRF for ERS requests for Enhanced Security, you can add the "use_csrf" tag:

```python
from pyiseers import ERS
ise = ERS(ise_node='192.168.0.10', ers_user='ers', ers_pass='supersecret', verify=False, disable_warnings=True, use_csrf=True)
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

#### Get device group(s) details

```python
# Provide a device_group_id 
ise.get_device_group(device_group_id="4b26b5b0-71a6-11eb-b5e0-52cf9299494c")

{'success': True,
 'response': {'id': '4b26b5b0-71a6-11eb-b5e0-52cf9299494c',
  'name': 'Device Type#All Device Types#NXOS',
  'description': '',
  'link': {'rel': 'self',
   'href': 'https://tst01-z0-vm-ise-01:9060/ers/config/networkdevicegroup/4b26b5b0-71a6-11eb-b5e0-52cf9299494c',
   'type': 'application/json'},
  'othername': 'Device Type'},
 'error': ''}


# Provide a partial group name to look for 
ise.get_device_group(name="NXOS")

{'success': True,
 'response': {'id': '4b26b5b0-71a6-11eb-b5e0-52cf9299494c',
  'name': 'Device Type#All Device Types#NXOS',
  'description': '',
  'link': {'rel': 'self',
   'href': 'https://tst01-z0-vm-ise-01:9060/ers/config/networkdevicegroup/4b26b5b0-71a6-11eb-b5e0-52cf9299494c',
   'type': 'application/json'},
  'othername': 'Device Type'},
 'error': ''}

# If more than one group found with for a name a list is returned
ise.get_device_group(name="Device Types")

[
  {'success': True,
  'response': {'id': '70c79c30-8bff-11e6-996c-525400b48521',
   'name': 'Device Type#All Device Types',
   'description': 'All Device Types',
   'link': {'rel': 'self',
    'href': 'https://tst01-z0-vm-ise-01:9060/ers/config/networkdevicegroup/70c79c30-8bff-11e6-996c-525400b48521',
    'type': 'application/json'},
   'othername': 'Device Type'},
  'error': ''},
 {'success': True,
  'response': {'id': 'ee45c0a0-7fbc-11eb-ac01-36750594a888',
   'name': 'Device Type#All Device Types#IOS-XE',
   'description': '',
   'link': {'rel': 'self',
    'href': 'https://tst01-z0-vm-ise-01:9060/ers/config/networkdevicegroup/ee45c0a0-7fbc-11eb-ac01-36750594a888',
    'type': 'application/json'},
   'othername': 'Device Type'},
  'error': ''},
 {'success': True,
  'response': {'id': '4b26b5b0-71a6-11eb-b5e0-52cf9299494c',
   'name': 'Device Type#All Device Types#NXOS',
   'description': '',
   'link': {'rel': 'self',
    'href': 'https://tst01-z0-vm-ise-01:9060/ers/config/networkdevicegroup/4b26b5b0-71a6-11eb-b5e0-52cf9299494c',
    'type': 'application/json'},
   'othername': 'Device Type'},
  'error': ''},
]
```

#### Add a new device group

```python
ise.add_device_group(name="Device Type#All Device Types#Python Device Type", description="From Python")

{'success': True,
 'response': 'Device Type#All Device Types#Python Device Type Added Successfully',
 'error': ''}
```

#### Update a device group

```python
ise.update_device_group(device_group_oid=group_id, name="Device Type#All Device Types#Updated Device Type", description="Update Description")

{'success': True,
 'response': 'e7db3e00-a36d-11eb-ac01-36750594a888 Updated Successfully',
 'error': ''}
```

#### Remove a device group

```python
ise.delete_device_group(name="Device Type#All Device Types#Python Device Type")

{'success': True,
 'response': 'Device Type#All Device Types#Python Device Type Deleted Successfully',
 'error': ''}
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

#### Update a device

```python
ise.update_device("PYTHON-DEVICE", tacacs_shared_secret="NEWTACACS")

{'success': True,
 'response': {'updatedField': [{'field': 'TacacsSettings.ConnectModeOptions',
    'oldValue': '',
    'newValue': 'ON_LEGACY'},
   {'field': 'TacacsSettings.SharedSecret', 'newValue': 'NEWTACACS'}]},
 'error': ''}
```

#### Delete a device

```python
ise.delete_device(device='testdevice03')

{'error': '', 'response': 'testdevice03 Deleted Successfully', 'success': True}
```

#### Get all Security Groups (SGTs)

```python
ise.get_sgts()

{'success': True, 'response': [('Contractors', '4f9c8050-8f9f-11ea-b8e4-ca18718347e2'), ('Employees', 'a34ae530-59a2-11ea-a6b9-26b516ce162b'), ('Guest', '440dd8b0-7da7-11ea-bb75-261e6ff61f42'), ('IoT_Devices', '55bd68f0-8f9f-11ea-b8e4-ca18718347e2'), ('IoT_Servers', '36369eb0-8fa0-11ea-b8e4-ca18718347e2'), ('Servers', '385cbd90-8fa1-11ea-b8e4-ca18718347e2'), ('TrustSec_Devices', '947832a0-8c01-11e6-996c-525400b48521'), ('Unknown', '92adf9f0-8c01-11e6-996c-525400b48521')], 'error': '', 'total': 8}
```

#### Get Specific SGT

```python
ise.get_sgt("Unknown")
ise.get_sgt(0)
ise.get_sgt("92adf9f0-8c01-11e6-996c-525400b48521")

{'success': True, 'response': {'id': '92adf9f0-8c01-11e6-996c-525400b48521', 'name': 'Unknown', 'description': 'Unknown Security Group', 'value': 0, 'generationId': '1', 'propogateToApic': False, 'link': {'rel': 'self', 'href': 'https://10.102.172.125:9060/ers/config/sgt/92adf9f0-8c01-11e6-996c-525400b48521', 'type': 'application/json'}}, 'error': ''}
```

#### Add a SGT

```python
ise.add_sgt("Python_Users", "Group used for all Python Users", 56789, return_object=True)

{'success': True, 'response': {'id': 'd4696690-97ba-11ea-9614-caf56bcd6712', 'name': 'Python_Users', 'description': 'Group used for all Python Users', 'value': 56789, 'generationId': '0', 'propogateToApic': False, 'link': {'rel': 'self', 'href': 'https://10.102.172.125:9060/ers/config/sgt/d4696690-97ba-11ea-9614-caf56bcd6712', 'type': 'application/json'}}, 'error': ''}
```

#### Update a SGT

```python
ise.update_sgt("d4696690-97ba-11ea-9614-caf56bcd6712", "Python_Tests", "Testing for Python Users", 45678, return_object=True)

{'success': True, 'response': {'id': 'd4696690-97ba-11ea-9614-caf56bcd6712', 'name': 'Python_Tests', 'description': 'Testing for Python Users', 'value': 45678, 'generationId': '0', 'propogateToApic': False, 'link': {'rel': 'self', 'href': 'https://10.102.172.125:9060/ers/config/sgt/d4696690-97ba-11ea-9614-caf56bcd6712', 'type': 'application/json'}}, 'error': ''}
```

#### Delete a SGT

```python
ise.delete_sgt("d4696690-97ba-11ea-9614-caf56bcd6712")

{'success': True, 'response': 'd4696690-97ba-11ea-9614-caf56bcd6712 Deleted Successfully', 'error': ''}
```

#### Get all Security Groups ACLs (SGACLs)

```python
ise.get_sgacls()

{'success': True, 'response': [('Block_All', '7c9b4a80-8fa1-11ea-b8e4-ca18718347e2'), ('Deny IP', '92919850-8c01-11e6-996c-525400b48521'), ('Deny_ICMP', 'c21dfa60-59a2-11ea-a6b9-26b516ce162b'), ('Deny_IP_Log', '0e6d3830-0684-11ea-ace5-42a6b55c5ca6'), ('Permit IP', '92951ac0-8c01-11e6-996c-525400b48521'), ('Permit_FTP', '761b9e50-7e01-11ea-bb75-261e6ff61f42'), ('Permit_IP_Log', '0e6aee40-0684-11ea-ace5-42a6b55c5ca6'), ('Permit_MQTT', '1470fa00-5a85-11ea-a6b9-26b516ce162b')], 'error': '', 'total': 8}
```

#### Get Specific SGACL

```python
ise.get_sgacl("Permit IP")
ise.get_sgacl("92951ac0-8c01-11e6-996c-525400b48521")

{'success': True, 'response': {'id': '92951ac0-8c01-11e6-996c-525400b48521', 'name': 'Permit IP', 'description': 'Permit IP SGACL', 'generationId': '0', 'aclcontent': 'permit ip', 'link': {'rel': 'self', 'href': 'https://10.102.172.125:9060/ers/config/sgacl/92951ac0-8c01-11e6-996c-525400b48521', 'type': 'application/json'}}, 'error': ''}
```

#### Add a SGACL

```python
ise.add_sgacl("Python_ACL", "Access List for Python Access", "IP_AGNOSTIC", ["permit tcp dst eq 80"], return_object=True)

{'success': True, 'response': {'id': '7a820000-97bb-11ea-9614-caf56bcd6712', 'name': 'Python_ACL', 'description': 'Access List for Python Access', 'generationId': '0', 'aclcontent': 'permit tcp dst eq 80', 'link': {'rel': 'self', 'href': 'https://10.102.172.125:9060/ers/config/sgacl/7a820000-97bb-11ea-9614-caf56bcd6712', 'type': 'application/json'}}, 'error': ''}
```

#### Update a SGACL

```python
ise.update_sgacl("7a820000-97bb-11ea-9614-caf56bcd6712", "Python_Access_List", "Python Access List", "IPV4", ["permit tcp src eq 80"], return_object=True)

{'success': True, 'response': {'id': '7a820000-97bb-11ea-9614-caf56bcd6712', 'name': 'Python_Access_List', 'description': 'Python Access List', 'generationId': '1', 'ipVersion': 'IPV4', 'aclcontent': 'permit tcp src eq 80', 'link': {'rel': 'self', 'href': 'https://10.102.172.125:9060/ers/config/sgacl/7a820000-97bb-11ea-9614-caf56bcd6712', 'type': 'application/json'}}, 'error': ''}
```

#### Get all TrustSec Egress Matrix Cells (Policies)

```python
ise.get_egressmatrixcells()

{'success': True, 'response': [('ANY-ANY', '92c1a900-8c01-11e6-996c-525400b48521'), ('Contractors-Servers', '5251ca60-8fa1-11ea-b8e4-ca18718347e2'), ('Contractors-IoT_Devices', 'de7859b0-8fa0-11ea-b8e4-ca18718347e2'), ('Employees-Servers', '5fb81e71-8fa1-11ea-b8e4-ca18718347e2'), ('Employees-Employees', 'd2d88280-59a2-11ea-a6b9-26b516ce162b'), ('Employees-IoT_Devices', 'e18ac9d1-8fa0-11ea-b8e4-ca18718347e2'), ('Employees-TrustSec_Devices', 'ee035030-59a2-11ea-a6b9-26b516ce162b'), ('Guest-IoT_Devices', 'e4d49da1-8fa0-11ea-b8e4-ca18718347e2'), ('IoT_Devices-IoT_Devices', 'b0eccdf0-8fa0-11ea-b8e4-ca18718347e2'), ('IoT_Devices-IoT_Servers', 'b7e6d880-8fa0-11ea-b8e4-ca18718347e2'), ('IoT_Devices-Contractors', 'c82308e0-8fa0-11ea-b8e4-ca18718347e2'), ('IoT_Devices-Employees', 'cb276f40-8fa0-11ea-b8e4-ca18718347e2'), ('IoT_Devices-Guest', 'ce1e4110-8fa0-11ea-b8e4-ca18718347e2'), ('IoT_Devices-TrustSec_Devices', 'd1e33851-8fa0-11ea-b8e4-ca18718347e2'), ('IoT_Devices-Unknown', 'd68d3860-8fa0-11ea-b8e4-ca18718347e2'), ('IoT_Servers-IoT_Devices', 'bc784780-8fa0-11ea-b8e4-ca18718347e2'), ('IoT_Servers-IoT_Servers', 'c069f410-8fa0-11ea-b8e4-ca18718347e2'), ('TrustSec_Devices-IoT_Devices', 'e94bcde1-8fa0-11ea-b8e4-ca18718347e2'), ('Unknown-IoT_Devices', 'f3e9da31-8fa0-11ea-b8e4-ca18718347e2')], 'error': '', 'total': 19}
```

#### Get Specific Egress Matrix Cell

```python
ise.get_egressmatrixcell("Default egress rule")
ise.get_egressmatrixcell(None, src_sgt="92bb1950-8c01-11e6-996c-525400b48521", dst_sgt="92bb1950-8c01-11e6-996c-525400b48521")

{'success': True, 'response': {'id': '92c1a900-8c01-11e6-996c-525400b48521', 'name': 'ANY-ANY', 'description': 'Default egress rule', 'sourceSgtId': '92bb1950-8c01-11e6-996c-525400b48521', 'destinationSgtId': '92bb1950-8c01-11e6-996c-525400b48521', 'matrixCellStatus': 'ENABLED', 'defaultRule': 'PERMIT_IP', 'sgacls': ['92951ac0-8c01-11e6-996c-525400b48521'], 'link': {'rel': 'self', 'href': 'https://10.102.172.125:9060/ers/config/egressmatrixcell/92c1a900-8c01-11e6-996c-525400b48521', 'type': 'application/json'}}, 'error': ''}
```

#### Add a Egress Matrix Cell

```python
ise.add_egressmatrixcell(source_sgt="Unknown", destination_sgt="TrustSec_Devices", default_rule="PERMIT_IP", return_object=True)

{'success': True, 'response': {'id': '6f76b621-97bf-11ea-9614-caf56bcd6712', 'name': 'Unknown-TrustSec_Devices', 'sourceSgtId': '92adf9f0-8c01-11e6-996c-525400b48521', 'destinationSgtId': '947832a0-8c01-11e6-996c-525400b48521', 'matrixCellStatus': 'ENABLED', 'defaultRule': 'PERMIT_IP', 'sgacls': ['92951ac0-8c01-11e6-996c-525400b48521'], 'link': {'rel': 'self', 'href': 'https://10.102.172.125:9060/ers/config/egressmatrixcell/6f76b621-97bf-11ea-9614-caf56bcd6712', 'type': 'application/json'}}, 'error': ''}
```

#### Update a Egress Matrix Cell

```python
ise.update_egressmatrixcell("6f76b621-97bf-11ea-9614-caf56bcd6712", source_sgt="Unknown", destination_sgt="TrustSec_Devices", default_rule="NONE", acls=["Deny IP"], description="Description", return_object=True)

{'success': True, 'response': {'id': '6f76b621-97bf-11ea-9614-caf56bcd6712', 'name': 'Unknown-TrustSec_Devices', 'description': 'Description', 'sourceSgtId': '92adf9f0-8c01-11e6-996c-525400b48521', 'destinationSgtId': '947832a0-8c01-11e6-996c-525400b48521', 'matrixCellStatus': 'ENABLED', 'defaultRule': 'DENY_IP', 'sgacls': ['92919850-8c01-11e6-996c-525400b48521'], 'link': {'rel': 'self', 'href': 'https://10.102.172.125:9060/ers/config/egressmatrixcell/6f76b621-97bf-11ea-9614-caf56bcd6712', 'type': 'application/json'}}, 'error': ''}
```

#### Delete a Egress Matrix Cell

```python
ise.delete_egressmatrixcell("6f76b621-97bf-11ea-9614-caf56bcd6712")

{'success': True, 'response': '6f76b621-97bf-11ea-9614-caf56bcd6712 Deleted Successfully', 'error': ''}
```

# History before namechange » 0.2.0

* Merged back from the work that [https://github.com/karrots](https://github.com/karrots) has done efter I paused the updates.  
* Converted to pipenv packages instead of requirements.txt
* Updated to ISE 2.4.x
* Merged back from the work that [https://github.com/msom](https://github.com/msom) has done with some good device fixes.
  * *One big thing is that module is now renamed from ise.cream to just ise.*
* First publish to PyPi with the help of [https://github.com/JonasKs](https://github.com/JonasKs).
* Add support for ISE CSRF and some TrustSec objects (SGT, SGACL, Egress Policy Matrix) [https://github.com/joshand](https://github.com/joshand).
* Merged [Enhancement to Device Group and Device Functions](https://github.com/falkowich/ise/pull/152) with a big thanks to [https://github.com/hpreston](https://github.com/hpreston)
  * New functions for devicegroups where added » add_device_group, update_device_group, delete_device_group.
  * New function to update devices where added » update_device
  * Updated get_device_group for looking up names
  * Updated add_device with new parameters and device_payload
* Updated dependensies for dev and prod, created new manual testcases, cleaned up the code with black.
