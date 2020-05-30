import vcr
import sys
sys.path.append('./')

from ise import ERS  # noqa E402
from pprint import pprint  # noqa E402
from config import uri, endpoint, endpoint_group, user, identity_group, device, device_group, trustsec  # noqa E402

my_vcr = vcr.VCR(
    serializer='json',
    cassette_library_dir='fixtures/vcr_cassettes',
    record_mode='once',
    match_on=['url', 'method', 'headers']
)


ise = ERS(ise_node=uri['ise_node'], ers_user=uri['ers_user'], ers_pass=uri['ers_pass'], verify=False,
          disable_warnings=True, timeout=15, use_csrf=uri['use_csrf'])


# Endpoint tests
@vcr.use_cassette('fixtures/vcr_cassettes/get_endpoints.yaml')
def test_get_endpoints():  # noqa D103

    r1 = ise.get_endpoints(size=1, page=1)
    assert r1['success'] is True
    assert r1['response'] <= [('00:00:00:00:00:02', '6bae9b50-35fb-11ea-a049-9e6928bbd7a4')]


@vcr.use_cassette('fixtures/vcr_cassettes/add_endpoint.yaml')
def test_add_endpoint():  # noqa D103

    r1 = ise.add_endpoint(endpoint['name'], endpoint['mac'], endpoint['group-id'])
    assert r1['success'] is True
    assert r1['response'] == 'test-endpoint Added Successfully'


@vcr.use_cassette('fixtures/vcr_cassettes/get_endpoint.yaml')
def test_get_endpoint():  # noqa D103

    r1 = ise.get_endpoint(endpoint['mac'])
    assert r1['success'] is True
    # TODO assert r1['response'] == 'test-endpoint Added Successfully'


@vcr.use_cassette('fixtures/vcr_cassettes/delete_endpoint.yaml')
def test_delete_endpoint():  # noqa D103

    r1 = ise.delete_endpoint(endpoint['mac'])
    assert r1['success'] is True
    assert r1['response'] == 'AA:BB:CC:00:11:22 Deleted Successfully'


@vcr.use_cassette('fixtures/vcr_cassettes/get_endpoint_groups.yaml')
def test_get_endpoint_groups():  # noqa D103

    r1 = ise.get_endpoint_groups(size=1, page=1)
    assert r1['success'] is True
    assert r1['response'] == [('ADM', 'b7ef3920-ca30-11e9-92d6-96c5f2507fd6', 'Admin network - [MAB]')]


@vcr.use_cassette('fixtures/vcr_cassettes/get_endpoint_group.yaml')
def test_get_endpoint_group():  # noqa D103

    r1 = ise.get_endpoint_group(endpoint_group['name'])
    assert r1['success'] is True
    # TODO assert r1['response'] == [('ADM', 'b7ef3920-ca30-11e9-92d6-96c5f2507fd6', 'Admin network - [MAB]')]


@vcr.use_cassette('fixtures/vcr_cassettes/get_identity_groups.yaml')
def test_get_identity_groups():  # noqa D103

    r1 = ise.get_identity_groups(size=1, page=1)
    assert r1['success'] is True
    # TODO assert r1['response'] == [('ADM', 'b7ef3920-ca30-11e9-92d6-96c5f2507fd6', 'Admin network - [MAB]')]


@vcr.use_cassette('fixtures/vcr_cassettes/get_identity_group.yaml')
def test_get_identity_group():  # noqa D103

    r1 = ise.get_identity_group(identity_group['name'])
    assert r1['success'] is True
    # TODO assert r1['response'] == [('ADM', 'b7ef3920-ca30-11e9-92d6-96c5f2507fd6', 'Admin network - [MAB]')]


@vcr.use_cassette('fixtures/vcr_cassettes/add_user.yaml')
def test_add_user():  # noqa D103

    r1 = ise.get_identity_group(identity_group['name'])
    identity_group_id = r1['response']['id']
    r2 = ise.add_user(
        user_id=user['user_id'],
        password=user['password'],
        user_group_oid=identity_group_id,
        enable=user['enable'],
        first_name=user['first_name'],
        last_name=user['last_name']
        )
    assert r2['success'] is True
    # TODO assert r1['response'] == [('ADM', 'b7ef3920-ca30-11e9-92d6-96c5f2507fd6', 'Admin network - [MAB]')]


@vcr.use_cassette('fixtures/vcr_cassettes/get_users.yaml')
def test_get_users():  # noqa D103

    r1 = ise.get_users(size=1, page=1)
    assert r1['success'] is True
    # TODO assert r1['response'] == [('ADM', 'b7ef3920-ca30-11e9-92d6-96c5f2507fd6', 'Admin network - [MAB]')]


@vcr.use_cassette('fixtures/vcr_cassettes/get_user.yaml')
def test_get_user():  # noqa D103

    r1 = ise.get_user(user['user_id'])
    assert r1['success'] is True
    # TODO assert r1['response'] == [('ADM', 'b7ef3920-ca30-11e9-92d6-96c5f2507fd6', 'Admin network - [MAB]')]


@vcr.use_cassette('fixtures/vcr_cassettes/delete_user.yaml')
def test_delete_user():  # noqa D103

    r1 = ise.delete_user(user['user_id'])
    assert r1['success'] is True
    # TODO assert r1['response'] == [('ADM', 'b7ef3920-ca30-11e9-92d6-96c5f2507fd6', 'Admin network - [MAB]')]


@vcr.use_cassette('fixtures/vcr_cassettes/get_device_groups.yaml')
def test_get_device_groups():
    r1 = ise.get_device_groups(size=1, page=1)
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/get_device_group.yaml')
def test_get_device_group():
    r1 = ise.get_device_group(device_group['oid'])
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/add_device.yaml')
def test_add_device():
    r1 = ise.add_device(
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
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/get_devices.yaml')
def test_get_devices():
    r1 = ise.get_devices(size=1, page=1)
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/get_device.yaml')
def test_get_device():
    r1 = ise.get_device(device['name'])
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/delete_device.yaml')
def test_delete_device():
    r1 = ise.delete_device(device['name'])
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/get_sgts.yaml')
def test_get_sgts():
    r1 = ise.get_sgts(size=1, page=1)
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/get_sgt.yaml')
def test_get_sgt():
    r1 = ise.get_sgt("Unknown")
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/add_sgt.yaml')
def test_add_sgt():
    r1 = ise.add_sgt(
        name="Python_Unit_Test",
        description="Unit Tests",
        value=trustsec["test_sgt_value"],
        return_object=True
    )
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/update_sgt.yaml')
def test_update_sgt():
    res = ise.get_sgt("Python_Unit_Test")
    id = res['response']['id']
    r1 = ise.update_sgt(
        id,
        name="Test_Unit_Python",
        description="Python Unit Tests",
        value=trustsec["test_sgt_value"]
    )
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/delete_sgt.yaml')
def test_delete_sgt():
    res = ise.get_sgt("Test_Unit_Python")
    id = res['response']['id']
    r1 = ise.delete_sgt(id)
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/get_sgacls.yaml')
def test_get_sgacls():
    r1 = ise.get_sgacls(size=1, page=1)
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/get_sgacl.yaml')
def test_get_sgacl():
    r1 = ise.get_sgacl("Permit IP")
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/add_sgacl.yaml')
def test_add_sgacl():
    r1 = ise.add_sgacl(
        name="Python_Unit_Test",
        description="Unit Tests",
        ip_version="IPV4",
        acl_content=["permit ip"],
        return_object=True
    )
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/update_sgacl.yaml')
def test_update_sgacl():
    res = ise.get_sgacl("Python_Unit_Test")
    id = res['response']['id']
    r1 = ise.update_sgacl(
        id,
        name="Test_Unit_Python",
        description="Python Unit Tests",
        ip_version="IPV4",
        acl_content=["permit ip"]
    )
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/delete_sgacl.yaml')
def test_delete_sgacl():
    res = ise.get_sgacl("Test_Unit_Python")
    id = res['response']['id']
    r1 = ise.delete_sgacl(id)
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/get_egressmatrixcells.yaml')
def test_get_egressmatrixcells():
    r1 = ise.get_egressmatrixcells(size=1, page=1)
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/get_egressmatrixcell.yaml')
def test_get_egressmatrixcell():
    r1 = ise.get_egressmatrixcell("Default egress rule")
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/add_egressmatrixcell.yaml')
def test_add_egressmatrixcell():
    r1 = ise.add_egressmatrixcell(
        trustsec["emc_source_sgt"],
        trustsec["emc_dest_sgt"],
        "PERMIT_IP",
        description="Python Unit Tests",
        return_object=True
    )
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/update_egressmatrixcell.yaml')
def test_update_egressmatrixcell():
    res = ise.get_egressmatrixcell("Python Unit Tests")
    id = res['response']['id']
    r1 = ise.update_egressmatrixcell(
        id,
        trustsec["emc_source_sgt"],
        trustsec["emc_dest_sgt"],
        "NONE",
        description="Test_Unit_Python",
        acls=[trustsec["test_assign_acl"]]
    )
    assert r1['success'] is True


@vcr.use_cassette('fixtures/vcr_cassettes/delete_egressmatrixcell(id).yaml')
def test_delete_egressmatrixcell():
    res = ise.get_egressmatrixcell("Test_Unit_Python")
    id = res['response']['id']
    r1 = ise.delete_egressmatrixcell(id)
    assert r1['success'] is True
