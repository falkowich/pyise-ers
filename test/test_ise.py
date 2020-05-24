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
