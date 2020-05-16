uri = {
    'ise_node': 'ip or fqdn',
    'ers_user': 'ers-user',
    'ers_pass': 'super-secret-password'
}

endpoint = {
    'name': 'test-endpoints',
    'mac': 'AA:BB:CC:00:11:22',
    'group-id': 'aa0e8b20-8bff-11e6-996c-525400b48521'
}

endpoint_group = {
    'name': 'Blacklist'
}

user = {
    'user_id': 'test-users',
    'password': 'TestUser123',
    'user_group_oid': 'Employee',
    'enable': 'TestUser123',
    'first_name': 'Firstname',
    'last_name': 'Lastname',
    'email': 'firstname.lastname@example.com',
    'description': 'Test Description'
}

identity_group = {
    'name': 'Employee'
}

device_group = {
    'oid': '70c79c30-8bff-11e6-996c-525400b48521'
}

device = {
    'name': 'test-device',
    'ip_address': '10.1.1.1',
    'radius_key': 'test-radius-key',
    'snmp_ro': 'snmp-ro-pass',
    'dev_group': 'Stage#Stage#Closed',
    'dev_location': 'Location#All Locations#Somewhere',
    'dev_type': 'Device Type#All Device Types#Something',
    'description': 'test-description',
    'snmp_v': 'TWO_C',
    'dev_profile': 'Cisco'
}

trustsec = {
    'test_sgt_value': 56789,
    'test_assign_acl': "92919850-8c01-11e6-996c-525400b48521",
    'emc_source_sgt': "Unknown",
    'emc_dest_sgt': "TrustSec_Devices"
}
