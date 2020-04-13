# This file will be fixed with pytest or unittest.
# But untill then this will work as a crude non-automagic testbed. // Falk

import sys
sys.path.append('./')

from ise import ERS  # noqa E402
from pprint import pprint  # noqa E402
from config import uri, endpoint, endpoint_group, user, identity_group, device, device_group  # noqa E402

ise = ERS(ise_node=uri['ise_node'], ers_user=uri['ers_user'], ers_pass=uri['ers_pass'], verify=False, disable_warnings=True, timeout=15)  # noqa: E501



def test_groups():

    groups = ise.get_endpoint_groups()['response']
    pprint(groups)

    group = ise.get_endpoint_group('Juniper-Device')['response']
    pprint(group)


def add_endpoint(endpoint):
    test = ise.add_endpoint(endpoint['name'], endpoint['mac'], endpoint['group-id'])  # noqa: E501
    if test['error']:
        print(test['response'])
    else:
        print('add_endpoint » OK')


def get_endpoints():
    test = ise.get_endpoints(size=100, page=1)
    if test['error']:
        print(test['response'])
    else:
        print('get_endpoints » OK')


def get_endpoint(endpoint):
    test = ise.get_endpoint(endpoint['mac'])
    if test['error']:
        print(test['response'])
    else:
        print('get_endpoint » OK')


def delete_endpoint(endpoint):
    test = ise.delete_endpoint(endpoint['mac'])
    if test['error']:
        print(test['response'])
    else:
        print('delete_endpoint » OK')


def get_endpoint_groups(size):
    test = ise.get_endpoint_groups(size=100, page=1)
    if test['error']:
        print(test['response'])
    else:
        print('get_endpoint_groups » OK')


def get_endpoint_group(endpoint_group):
    test = ise.get_endpoint_group(endpoint_group['name'])
    if test['error']:
        print(test['response'])
    else:
        print('get_endpoint_group » OK')


def get_identity_groups():
    test = ise.get_identity_groups(size=100, page=1)
    if test['error']:
        print(test['response'])
    else:
        print('get_identity_groups » OK')


def get_identity_group(identity_group):
    test = ise.get_identity_group(identity_group['name'])
    if test['error']:
        print(test['response'])
    else:
        print('get_identity_group » OK')

    identity_group_id = test['response']['id']

    return identity_group_id


def add_user(user, identity_group_id):
    test = ise.add_user(
        user_id=user['user_id'],
        password=user['password'],
        user_group_oid=identity_group_id,
        enable=user['enable'],
        first_name=user['first_name'],
        last_name=user['last_name']
        )
    if test['error']:
        print(test['response'])
    else:
        print('add_user » OK')


def get_users():
    test = ise.get_users(size=100, page=1)
    if test['error']:
        print(test['response'])
    else:
        print('get_users » OK')


def get_user(user):
    test = ise.get_user(user['user_id'])
    if test['error']:
        print(test['response'])
    else:
        print('get_user » OK')


def delete_user(user):
    test = ise.delete_user(user['user_id'])
    if test['error']:
        print(test['response'])
    else:
        print('delete_user » OK')


def get_device_groups():
    test = ise.get_device_groups(size=100, page=1)
    if test['error']:
        print(test['response'])
    else:
        print('get_device_groups » OK')
    device_group = test['response'][0][1]

    return device_group


def get_device_group(device_group):
    test = ise.get_device_group(device_group['oid'])
    if test['error']:
        print(test['response'])
    else:
        print('get_device_group » OK')


def add_device(device):
    test = ise.add_device(
        name=device['name'],
        ip_address=device['ip_address'],
        radius_key=device['radius_key'],
        snmp_ro=device['snmp_ro'],
        dev_group=device['dev_group'],
        dev_location=device['dev_location'],
        dev_type=device['dev_type'],
        description=device['description'],
        snmp_v=device['snmp_v'],
        dev_profile=device['dev_profile']
    )

    if test['error']:
        print(test['response'])
    else:
        print('add_device » OK')


def get_devices():
    test_get = ise.get_devices(size=100, page=1)
    if test_get['error']:
        print(test_get['response'])
    else:
        print('get_devices » OK')


def get_device(device):
    test = ise.get_device(device['name'])
    if test['error']:
        print(test['response'])
    else:
        print('get_device » OK')


def delete_device(device):
    test = ise.delete_device(device['name'])
    if test['error']:
        print(test['response'])
    else:
        print('delete_device » OK')


if __name__ == "__main__":

    # Endpoint tests
    add_endpoint(endpoint)
    get_endpoints()
    get_endpoint(endpoint)
    delete_endpoint(endpoint)

    # EndpointGroup tests
    get_endpoint_groups(21)
    get_endpoint_group(endpoint_group)

    # User tests
    get_identity_groups()
    identity_group_id = get_identity_group(identity_group)
    add_user(user, identity_group_id)
    get_users()
    get_user(user)
    delete_user(user)

    # Device tests
    get_device_groups()
    get_device_group(device_group)
    add_device(device)
    get_devices()
    get_device(device)
    delete_device(device)
    #  get_object()  # TODO
