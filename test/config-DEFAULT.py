
## 2.7 conf
#uri = {
#        "ise_version": "2.7",
#        "ise_node": "ip/fqdn",
#        "ers_user": "ers-operator",
#        "ers_pass": "Password27",
#        "use_csrf": False,
#    }

## 3.0 conf
#uri = {
#        "ise_version": "3.0",
#        "ise_node": "ip/fqdn",
#        "ers_user": "ers-operator",
#        "ers_pass": "Password30",
#        "use_csrf": False,
#    }

## 3.1 conf
#uri = {
#        "ise_version": "3.1",
#        "ise_node": "ip/fqdn",
#        "ers_user": "ers-operator",
#        "ers_pass": "Password31",
#        "use_csrf": False,
#    }

endpoint = {
    "name": "test-endpoint",
    "mac": "AA:BB:CC:00:11:22",
    "faulty_mac": "AA:BB:CC:00:11:2Q",
    "group-id": "aa0e8b20-8bff-11e6-996c-525400b48521",
}

endpoint_group = {
    "name": "TestEndpointGroup",
    "description": "TestEndpointGroup Endpoint group description",
}

user = {
    "user_id": "test-user",
    "password": "TestUser123",
    "user_group_oid": "Employee",
    "enable": "TestUser123",
    "first_name": "Firstname",
    "last_name": "Lastname",
    "email": "firstname.lastname@example.com",
    "description": "Test Description",
}

identity_group = {"name": "Employee"}

device_group = {
    "name": "Device Type#All Device Types#Python Device Type",
    "description": "From Python",
}

device = {
    "name": "test-name",
    "name_mip": "test-name-multiple_ip",
    "new_name": "new-test-name",
    "ip_address": "10.1.1.1",
    "ip_addresses": ["10.1.1.2", "10.1.1.3"],
    "mask": "32",
    "description": "test-description",
    "dev_group": "testgroup#testgroup",
    "dev_location": "Location#All Locations",
    "dev_type": "Device Type#All Device Types",
    "dev_ipsec": "IPSEC#Is IPSEC Device#No",
    "radius_key": "test-radius-key",
    "snmp_ro": "snmp-ro-pass",
    "dev_profile": "Cisco",
    "tacacs_shared_secret": "testsecret",
    "tacacs_connect_mode_options": "ON_LEGACY",
    "coa_port": "1700",
    "snmp_version": "TWO_C",
    "snmp_polling_interval": "3600",
    "snmp_link_trap_query": "true",
    "snmp_mac_trap_query": "true",
    "snmp_originating_policy_services_node": "Auto",
}



device_payload = {
    "name": device["name"],
    "description": device["description"],
    "profileName": device["dev_profile"],
    "coaPort": device["coa_port"],
    "NetworkDeviceIPList": [
        {
            "ipaddress": device["ip_address"],
            "mask": device["mask"],
        }
    ],
    "NetworkDeviceGroupList": [
        device["dev_type"],
        device["dev_location"],
        device["dev_ipsec"],
    ],
}

updated_device_payload = {
    "name": device["name"],
    "description": device["description"],
    "profileName": device["dev_profile"],
    "coaPort": device["coa_port"],
    "NetworkDeviceIPList": [
        {
            "ipaddress": device["ip_address"],
            "mask": device["mask"],
        }
    ],
    "NetworkDeviceGroupList": [
        device["dev_type"],
        device["dev_location"],
        device["dev_ipsec"],
    ],
}

trustsec = {
    "test_sgt_value": 56789,
    "test_assign_acl": "92919850-8c01-11e6-996c-525400b48521",
    "emc_source_sgt": "Unknown",
    "emc_dest_sgt": "TrustSec_Devices",
}
