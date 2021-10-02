import pytest
import sys
import urllib3

sys.path.append("./")

from pyiseers import ERS  # noqa E402
from pprint import pprint  # noqa E402
from config import (  # noqa E402
    uri_30,
    endpoint,
    endpoint_group,
    user,
    identity_group,
    device,
    device_payload,
    device_group,
    trustsec,
)

urllib3.disable_warnings()


@pytest.fixture(scope="module")
def vcr_config():
    return {
        "filter_headers": ["authorization"],
        "ignore_localhost": True,
    }


uri = uri_30


ise = ERS(
    ise_node=uri["ise_node"],
    ers_user=uri["ers_user"],
    ers_pass=uri["ers_pass"],
    verify=False,
    disable_warnings=True,
    timeout=15,
    use_csrf=uri["use_csrf"],
)


@pytest.mark.vcr
def test_add_endpoint():  # noqa D103

    r1 = ise.add_endpoint(endpoint["name"], endpoint["mac"], endpoint["group-id"])
    assert r1["success"] is True
    assert r1["response"] == "test-endpoint Added Successfully"


# Endpoint tests
@pytest.mark.vcr
def test_get_endpoints():  # noqa D103

    r1 = ise.get_endpoints(size=1, page=1)
    assert r1["success"] is True
    assert "AA:BB:CC:00:11:22" in str(r1["response"])


@pytest.mark.vcr
def test_get_endpoint():  # noqa D103

    r1 = ise.get_endpoint(endpoint["mac"])
    assert r1["success"] is True
    assert "'name': 'AA:BB:CC:00:11:22'" in str(r1["response"])


@pytest.mark.vcr
def test_delete_endpoint():  # noqa D103
    r1 = ise.delete_endpoint(endpoint["mac"])
    assert r1["success"] is True
    assert r1["response"] == "AA:BB:CC:00:11:22 Deleted Successfully"


@pytest.mark.vcr
def test_get_endpoint_groups():  # noqa D103

    r1 = ise.get_endpoint_groups(size=1, page=1)
    assert r1["success"] is True
    assert (
        "('Android', 'ffa36b00-8bff-11e6-996c-525400b48521', 'Identity Group for Profile: Android')"
        in str(r1["response"])
    )


@pytest.mark.vcr
def test_get_endpoint_group():  # noqa D103

    r1 = ise.get_endpoint_group(endpoint_group["name"])
    assert r1["success"] is True
    assert "'description': 'Unknown Identity Group'" in str(r1["response"])


@pytest.mark.vcr
def test_get_identity_groups():  # noqa D103

    r1 = ise.get_identity_groups(size=1, page=1)
    assert r1["success"] is True
    assert r1["response"] == [
        (
            "ALL_ACCOUNTS (default)",
            "a176c430-8c01-11e6-996c-525400b48521",
            "Default ALL_ACCOUNTS (default) User Group",
        )
    ]


@pytest.mark.vcr
def test_get_identity_group():  # noqa D103

    r1 = ise.get_identity_group(identity_group["name"])
    assert r1["success"] is True
    assert "Default Employee User Group" in str(r1["response"])


@pytest.mark.vcr
def test_add_user():  # noqa D103

    r1 = ise.get_identity_group(identity_group["name"])
    identity_group_id = r1["response"]["id"]
    r2 = ise.add_user(
        user_id=user["user_id"],
        password=user["password"],
        user_group_oid=identity_group_id,
        enable=user["enable"],
        first_name=user["first_name"],
        last_name=user["last_name"],
    )
    assert r2["success"] is True
    assert r2["response"] == "test-user Added Successfully"


@pytest.mark.vcr
def test_get_users():  # noqa D103

    r1 = ise.get_users(size=1, page=1)
    assert r1["success"] is True
    assert "test-user" in str(r1["response"])


@pytest.mark.vcr
def test_get_user():  # noqa D103

    r1 = ise.get_user(user["user_id"])
    assert r1["success"] is True
    assert ("Firstname" and "Lastname") in str(r1["response"])


@pytest.mark.vcr
def test_delete_user():  # noqa D103

    r1 = ise.delete_user(user["user_id"])
    assert r1["success"] is True
    assert r1["response"] == "test-user Deleted Successfully"


@pytest.mark.vcr
def test_add_device_group():
    r1 = ise.add_device_group(
        name=device_group["name"], description=device_group["description"]
    )
    assert r1["success"] is True
    assert "Device Type#All Device Types#Python Device Type Added" in str(
        r1["response"]
    )


@pytest.mark.vcr
def test_get_device_groups():
    r1 = ise.get_device_groups(size=1, page=1)
    assert r1["success"] is True
    assert r1["response"] == [
        (
            "Device Type#All Device Types",
            "70c79c30-8bff-11e6-996c-525400b48521",
            "All Device Types",
        )
    ]


@pytest.mark.vcr
def test_get_device_group_from_name():
    r1 = ise.get_device_group(name="Python")
    assert r1["success"] is True
    assert "Device Type#All Device Types#Python Device Type" in str(r1["response"])


@pytest.mark.vcr
def test_get_device_group():
    r1 = ise.get_device_group(name="Python")
    device_group_id = r1["response"]["id"]
    r2 = ise.get_device_group(device_group_id)
    assert r2["success"] is True
    assert "Device Type#All Device Types#Python Device Type" in str(r2["response"])


@pytest.mark.vcr
def test_update_device_group():
    r1 = ise.get_device_group(name="Python")
    device_group_id = r1["response"]["id"]
    r2 = ise.update_device_group(
        device_group_oid=device_group_id,
        name="Device Type#All Device Types#Updated Device Type",
        description="Update Description",
    )
    assert r2["success"] is True
    assert "Updated Successfully" in str(r2["response"])


@pytest.mark.vcr
def test_delete_device_group():
    r1 = ise.delete_device_group(
        name="Device Type#All Device Types#Updated Device Type"
    )
    assert r1["success"] is True
    assert "Device Type#All Device Types#Updated Device Type Deleted" in str(
        r1["response"]
    )


@pytest.mark.vcr
def test_add_device():
    r0 = ise.add_device_group(
        name=device["dev_group"], description="temporary testgroup"
    )

    r1 = ise.add_device(
        name=device["name"],
        ip_address=device["ip_address"],
        mask=device["mask"],
        description=device["description"],
        dev_group=device["dev_group"],
        dev_location=device["dev_location"],
        dev_type=device["dev_type"],
        dev_ipsec=device["dev_ipsec"],
        radius_key=device["radius_key"],
        snmp_ro=device["snmp_ro"],
        dev_profile=device["dev_profile"],
        tacacs_shared_secret=device["tacacs_shared_secret"],
        tacacs_connect_mode_options=device["tacacs_connect_mode_options"],
        coa_port=device["coa_port"],
        snmp_version=device["snmp_version"],
        snmp_polling_interval=device["snmp_polling_interval"],
        snmp_link_trap_query=device["snmp_link_trap_query"],
        snmp_mac_trap_query=device["snmp_mac_trap_query"],
        snmp_originating_policy_services_node=device[
            "snmp_originating_policy_services_node"
        ],
    )
    assert r1["success"] is True
    assert r1["response"] == "test-name Added Successfully"

    r2 = ise.delete_device_group(name=device["dev_group"])


@pytest.mark.vcr
def test_get_devices():
    r1 = ise.get_devices(size=100, page=1)
    assert r1["success"] is True
    assert "test-name" in str(r1["response"])


@pytest.mark.vcr
def test_get_device():
    r1 = ise.get_device(device["name"])
    assert r1["success"] is True
    assert "test-name" in str(r1["response"])


@pytest.mark.vcr
def test_delete_device():
    r1 = ise.delete_device(device["name"])
    assert r1["success"] is True
    assert r1["response"] == "test-name Deleted Successfully"


@pytest.mark.vcr
def test_add_device_payload():
    r1 = ise.add_device(device_payload=device_payload)
    assert r1["success"] is True
    assert r1["response"] == "test-name Added Successfully"


@pytest.mark.vcr
def test_update_device():
    r1 = ise.update_device(name=device["name"], new_name=device["new_name"])
    assert r1["success"] is True
    # TODO assert r1["response"]["updatedField"][0]["newValue"] == "new-test-name"

    # cleanup
    ise.delete_device(device["new_name"])


@pytest.mark.vcr
def test_get_sgts():
    r1 = ise.get_sgts(size=1, page=1)
    assert r1["success"] is True


@pytest.mark.vcr
def test_get_sgt():
    r1 = ise.get_sgt("Unknown")
    assert r1["success"] is True


@pytest.mark.vcr
def test_add_sgt():
    r1 = ise.add_sgt(
        name="Python_Unit_Test",
        description="Unit Tests",
        value=trustsec["test_sgt_value"],
        return_object=True,
    )
    assert r1["success"] is True


@pytest.mark.vcr
def test_update_sgt():
    res = ise.get_sgt("Python_Unit_Test")
    id = res["response"]["id"]
    r1 = ise.update_sgt(
        id,
        name="Test_Unit_Python",
        description="Python Unit Tests",
        value=trustsec["test_sgt_value"],
    )
    assert r1["success"] is True


@pytest.mark.vcr
def test_delete_sgt():
    res = ise.get_sgt("Test_Unit_Python")
    id = res["response"]["id"]
    r1 = ise.delete_sgt(id)
    assert r1["success"] is True


@pytest.mark.vcr
def test_get_sgacls():
    r1 = ise.get_sgacls(size=1, page=1)
    assert r1["success"] is True


@pytest.mark.vcr
def test_get_sgacl():
    r1 = ise.get_sgacl("Permit IP")
    assert r1["success"] is True


@pytest.mark.vcr
def test_add_sgacl():
    r1 = ise.add_sgacl(
        name="Python_Unit_Test",
        description="Unit Tests",
        ip_version="IPV4",
        acl_content=["permit ip"],
        return_object=True,
    )
    assert r1["success"] is True


@pytest.mark.vcr
def test_update_sgacl():
    res = ise.get_sgacl("Python_Unit_Test")
    id = res["response"]["id"]
    r1 = ise.update_sgacl(
        id,
        name="Test_Unit_Python",
        description="Python Unit Tests",
        ip_version="IPV4",
        acl_content=["permit ip"],
    )
    assert r1["success"] is True


@pytest.mark.vcr
def test_delete_sgacl():
    res = ise.get_sgacl("Test_Unit_Python")
    id = res["response"]["id"]
    r1 = ise.delete_sgacl(id)
    assert r1["success"] is True


@pytest.mark.vcr
def test_get_egressmatrixcells():
    r1 = ise.get_egressmatrixcells(size=1, page=1)
    assert r1["success"] is True


@pytest.mark.vcr
def test_get_egressmatrixcell():
    r1 = ise.get_egressmatrixcell("Default egress rule")
    assert r1["success"] is True


@pytest.mark.vcr
def test_add_egressmatrixcell():
    r1 = ise.add_egressmatrixcell(
        trustsec["emc_source_sgt"],
        trustsec["emc_dest_sgt"],
        "PERMIT_IP",
        description="Python Unit Tests",
        return_object=True,
    )
    assert r1["success"] is True


@pytest.mark.vcr
def test_update_egressmatrixcell():
    res = ise.get_egressmatrixcell("Python Unit Tests")
    id = res["response"]["id"]
    r1 = ise.update_egressmatrixcell(
        id,
        trustsec["emc_source_sgt"],
        trustsec["emc_dest_sgt"],
        "NONE",
        description="Test_Unit_Python",
        acls=[trustsec["test_assign_acl"]],
    )
    assert r1["success"] is True


@pytest.mark.vcr
def test_delete_egressmatrixcell():
    res = ise.get_egressmatrixcell("Test_Unit_Python")
    id = res["response"]["id"]
    r1 = ise.delete_egressmatrixcell(id)
    assert r1["success"] is True
