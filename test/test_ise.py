import sys

import pytest
import urllib3

sys.path.append("./pyise_ers")

from pprint import pprint  # noqa E402

from config import (  # noqa E402
    device,
    device_group,
    device_payload,
    endpoint,
    endpoint_group,
    identity_group,
    trustsec,
    updated_device_payload,
    uri,
    user,
)

from pyiseers import ERS  # noqa E402

urllib3.disable_warnings()


# @pytest.fixture(scope="module")
# def vcr_config():
#    return {
#        "filter_headers": ["authorization"],
#        "ignore_localhost": True,
#    }


uri = uri

fail_ise = ERS(
    ise_node=uri["ise_node"],
    ers_user="non_active_testuser",
    ers_pass=uri["ers_pass"],
    verify=False,
    disable_warnings=True,
    timeout=15,
    use_csrf=uri["use_csrf"],
)


# @pytest.mark.vcr
def test_fail_connection_401():  # noqa D103
    r1 = fail_ise.add_endpoint(endpoint["name"], endpoint["mac"], endpoint["group-id"])
    if uri["ise_version"] == "2.7":
        assert r1["response"] == "Unauthorized"
    else:
        assert r1["response"] == ""
    assert r1["error"] == 401


ise = ERS(
    ise_node=uri["ise_node"],
    ers_user=uri["ers_user"],
    ers_pass=uri["ers_pass"],
    verify=False,
    disable_warnings=True,
    timeout=15,
    use_csrf=uri["use_csrf"],
)


# @pytest.mark.vcr
def test_add_endpoint():  # noqa D103
    r1 = ise.add_endpoint(endpoint["name"], endpoint["mac"], endpoint["group-id"])
    assert r1["success"] is True
    assert r1["response"] == "test-endpoint Added Successfully"


def test_add_endpoint_mac_fail():  # noqa D103
    with pytest.raises(
        Exception, match="AA:BB:CC:00:11:2Q. Must be in the form of AA:BB:CC:00:11:22"
    ):
        r1 = ise.add_endpoint(
            endpoint["name"], endpoint["faulty_mac"], endpoint["group-id"]
        )


# @pytest.mark.vcr
def test_get_endpoints():  # noqa D103
    r1 = ise.get_endpoints(size=1, page=1)
    assert r1["success"] is True
    assert "AA:BB:CC:00:11:22" in str(r1["response"])


# @pytest.mark.vcr
def test_get_endpoints_groupid():  # noqa D103
    r1 = ise.get_endpoints(groupID=endpoint["group-id"], size=1, page=1)
    assert r1["success"] is True
    assert "AA:BB:CC:00:11:22" in str(r1["response"])


# @pytest.mark.vcr
def test_get_endpoint():  # noqa D103
    r1 = ise.get_endpoint(endpoint["mac"])
    assert r1["success"] is True
    assert "'name': 'AA:BB:CC:00:11:22'" in str(r1["response"])


# @pytest.mark.vcr
def test_get_endpoint_not_found():  # noqa D103
    r1 = ise.get_endpoint("00:00:00:00:00:00:")
    assert r1["success"] is False
    assert "not found" in str(r1["response"])
    assert r1["error"] == 404


# @pytest.mark.vcr
def test_get_endpoint_faulty_mac():  # noqa D103
    with pytest.raises(
        Exception, match="AA:BB:CC:00:11:2Q. Must be in the form of AA:BB:CC:00:11:22"
    ):
        r1 = ise.get_endpoint("AA:BB:CC:00:11:2Q")


# @pytest.mark.vcr
def test_delete_endpoint():  # noqa D103
    r1 = ise.delete_endpoint(endpoint["mac"])
    assert r1["success"] is True
    assert r1["response"] == "AA:BB:CC:00:11:22 Deleted Successfully"


# @pytest.mark.vcr
def test_delete_endpoint_not_found():  # noqa D103
    r1 = ise.delete_endpoint("00:00:00:00:00:00")
    assert r1["success"] is False
    assert r1["response"] == "00:00:00:00:00:00 not found"
    assert r1["error"] == 404


# @pytest.mark.vcr
def test_get_endpoint_groups():  # noqa D103
    r1 = ise.get_endpoint_groups(size=1, page=1)
    assert r1["success"] is True
    assert (
        "('Android', 'ffa36b00-8bff-11e6-996c-525400b48521', 'Identity Group for Profile: Android')"
        in str(r1["response"])
    )


# @pytest.mark.vcr
def test_add_endpoint_group():  # noqa D103
    r1 = ise.add_endpoint_group(endpoint_group["name"], endpoint_group["description"])
    epg = endpoint_group["name"]
    assert r1["success"] is True
    assert f"{epg} Added Successfully" in r1["response"]


# @pytest.mark.vcr
def test_get_endpoint_group():  # noqa D103
    r1 = ise.get_endpoint_group(endpoint_group["name"])
    epg = endpoint_group["name"]
    assert r1["success"] is True
    assert f"'name': '{epg}'" in str(r1["response"])


# @pytest.mark.vcr
def test_get_endpoint_group_group_id():  # noqa D103
    r1 = ise.get_endpoint_group(endpoint["group-id"])
    assert r1["success"] is True
    assert "'description': 'Unknown Identity Group'" in str(r1["response"])


# @pytest.mark.vcr
def test_get_endpoint_group_fail():  # noqa D103
    r1 = ise.get_endpoint_group("NO GROUP THAT EXISTS")
    assert r1["success"] is False
    assert r1["response"] == None
    assert r1["error"] == 200


# @pytest.mark.vcr
def test_delete_endpoint_group():  # noqa D103
    r1 = ise.get_endpoint_group(endpoint_group["name"])
    r2 = ise.delete_endpoint_group(r1["response"]["id"])
    assert f"{r1['response']['id']} Deleted Successfully" in str(r2["response"])


def test_delete_endpoint_group_fail():  # noqa D103
    r1 = ise.delete_endpoint_group("does_not_exist")
    assert r1["success"] is False
    assert r1["error"] == 404
    assert "does_not_exist not found"


# @pytest.mark.vcr
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


# @pytest.mark.vcr
def test_get_identity_group():  # noqa D103
    r1 = ise.get_identity_group(identity_group["name"])
    assert r1["success"] is True
    assert "Default Employee User Group" in str(r1["response"])


# @pytest.mark.vcr
def test_get_identity_group_not_found():  # noqa D103
    r1 = ise.get_identity_group("znonexistantz")
    assert r1["success"] is False
    assert r1["error"] == 404
    assert "znonexistantz not found" in r1["response"]


# @pytest.mark.vcr
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
        email=user["email"],
    )
    assert r2["success"] is True
    assert r2["response"] == "test-user Added Successfully"


# @pytest.mark.vcr
def test_get_users():  # noqa D103
    r1 = ise.get_users(size=1, page=1)
    assert r1["success"] is True
    assert "test-user" in str(r1["response"])


# @pytest.mark.vcr
def test_get_user():  # noqa D103
    r1 = ise.get_user(user["user_id"])
    assert r1["success"] is True
    assert ("Firstname" and "Lastname") in str(r1["response"])


# @pytest.mark.vcr
def test_get_user_not_found():  # noqa D103
    r1 = ise.get_user(99999999999999999)
    assert r1["success"] is False
    assert r1["error"] == 404

# @pytest.mark.vcr
def test_get_user_by_email():  # noqa D103
    r1 = ise.get_user_by_email(user["email"])
    assert r1["success"] is True
    assert ("Firstname" and "Lastname") in str(r1["response"])


# @pytest.mark.vcr
def test_get_user_by_email_not_found():  # noqa D103
    r1 = ise.get_user_by_email("this.user@does.not.exist")
    assert r1["success"] is False
    assert r1["error"] == 404

# @pytest.mark.vcr
def test_delete_user():  # noqa D103
    r1 = ise.delete_user(user["user_id"])
    assert r1["success"] is True
    assert r1["response"] == "test-user Deleted Successfully"


# @pytest.mark.vcr
def test_delete_user_not_found():  # noqa D103
    r1 = ise.delete_user(99999999999999999)
    assert r1["success"] is False
    assert r1["response"] == "99999999999999999 not found"
    assert r1["error"] == 404



def test_get_admin_user():  # noqa D103
    r1 = ise.get_admin_user("admin")
    assert r1["success"] is True
    assert ("name" and "description" and "adminGroups") in str(r1["response"])


# @pytest.mark.vcr
def test_get_admin_user_not_found():  # noqa D103
    r1 = ise.get_admin_user("not_an_admin_user")
    assert r1["success"] is False
    assert r1["error"] == 404



# @pytest.mark.vcr
def test_add_device_group():
    r1 = ise.add_device_group(
        name=device_group["name"], description=device_group["description"]
    )
    assert r1["success"] is True
    assert "Device Type#All Device Types#Python Device Type Added" in str(
        r1["response"]
    )


# @pytest.mark.vcr
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


# @pytest.mark.vcr
def test_get_device_group_from_name():
    r1 = ise.get_device_group(name="Python")
    assert r1["success"] is True
    assert "Device Type#All Device Types#Python Device Type" in str(r1["response"])


# @pytest.mark.vcr
def test_get_device_group_from_name_not_found():
    r1 = ise.get_device_group(name="NOFOUNDPython")
    assert r1["success"] is False
    assert r1["error"] == 404


# @pytest.mark.vcr
def test_get_device_group():
    r1 = ise.get_device_group(name="Python")
    device_group_id = r1["response"]["id"]
    r2 = ise.get_device_group(device_group_id)
    assert r2["success"] is True
    assert "Device Type#All Device Types#Python Device Type" in str(r2["response"])


# @pytest.mark.vcr
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


# @pytest.mark.vcr
def test_delete_device_group():
    r1 = ise.delete_device_group(
        name="Device Type#All Device Types#Updated Device Type"
    )
    assert r1["success"] is True
    assert "Device Type#All Device Types#Updated Device Type Deleted" in str(
        r1["response"]
    )


# @pytest.mark.vcr
def test_delete_device_group_not_found():
    r1 = ise.delete_device_group(
        name="NOTFOUNDDevice Type#NOTFOUNDAll Device Types#NOTFOUNDUpdated Device Type"
    )
    assert r1["success"] is False
    assert "not found" in r1["response"]
    assert r1["error"] == 404


# @pytest.mark.vcr
def test_update_device_group_not_found():
    r2 = ise.update_device_group(
        device_group_oid="99999999-99999999",
        name="Device Type#All Device Types#Updated Device Type",
        description="Update Description",
    )
    assert r2["success"] is False
    assert r2["error"] == 404


# @pytest.mark.vcr
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


# @pytest.mark.vcr
def test_add_device_no_name():
    r1 = ise.add_device(
        name="",
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
    assert r1["success"] is False
    assert "You must provide either" in r1["error"]


# @pytest.mark.vcr
def test_get_devices():
    r1 = ise.get_devices(size=100, page=1)
    assert r1["success"] is True
    assert "test-name" in str(r1["response"])


# @pytest.mark.vcr
def test_get_device():
    r1 = ise.get_device(device["name"])
    assert r1["success"] is True
    assert "test-name" in str(r1["response"])


# @pytest.mark.vcr
def test_get_device_not_found():
    r1 = ise.get_device("SNART_E_DET_JUL")
    assert r1["success"] is False
    assert "not found" in str(r1["response"])
    assert r1["error"] == 404


# @pytest.mark.vcr
def test_delete_device():
    r1 = ise.delete_device(device["name"])
    assert r1["success"] is True
    assert r1["response"] == "test-name Deleted Successfully"


# @pytest.mark.vcr
def test_delete_device_not_found():
    r1 = ise.delete_device("SNART E DET SOMMAR")
    assert r1["success"] is False
    assert r1["response"] == "SNART E DET SOMMAR not found"
    assert r1["error"] == 404


# @pytest.mark.vcr
def test_add_device_payload():
    r1 = ise.add_device(device_payload=device_payload)
    assert r1["success"] is True
    assert r1["response"] == "test-name Added Successfully"


# @pytest.mark.vcr
def test_update_device_name():
    r1 = ise.update_device(name=device["name"], new_name=device["new_name"])

    assert r1["success"] is True
    assert "test-name" in str(r1["response"])
    assert "new-test-name" in str(r1["response"])


# @pytest.mark.vcr
def test_update_device_dev_profile():
    r1 = ise.update_device(name=device["new_name"], dev_profile="HPWired")

    assert r1["success"] is True
    assert "HPWired" in str(r1["response"])


# @pytest.mark.vcr
def test_update_device_coa_port():
    r1 = ise.update_device(name=device["new_name"], coa_port="1701")

    assert r1["success"] is True
    assert "1701" in str(r1["response"])


# @pytest.mark.vcr
def test_update_device_ip():
    r1 = ise.update_device(name=device["new_name"], ip_address="10.1.1.2", mask=32)

    assert r1["success"] is True
    assert "10.1.1.2" in str(r1["response"])
    assert "32" in str(r1["response"])


# @pytest.mark.vcr
def test_update_device_disable_radius_error():
    r1 = ise.update_device(name=device["new_name"], disable_radius=True)
    assert r1["success"] is False
    assert (
        r1["error"]
        == "Error: ERS API doesn't support disabling RADIUS. You'll need to delete/add the device"
    )


# @pytest.mark.vcr
def test_update_device_radius_key():
    r1 = ise.update_device(name=device["new_name"], radius_key="new-test-radius-key")

    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_tacacs_shared_secret():
    r1 = ise.update_device(
        name=device["new_name"], tacacs_shared_secret="new-tacacs-shared-secret"
    )

    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_tacacs_connect_mode():
    r1 = ise.update_device(
        name=device["new_name"], tacacs_connect_mode_options="ON_DRAFT_COMPLIANT"
    )

    assert r1["success"] is True
    assert "ON_DRAFT_COMPLIANT" in str(r1["response"])


# @pytest.mark.vcr
def test_update_device_disable_tacacs():
    r1 = ise.update_device(name=device["new_name"], disable_tacacs=True)

    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_device_description():
    r1 = ise.update_device(name=device["new_name"], description="new-description")

    assert r1["success"] is True
    assert "new-description" in str(r1["response"])


# @pytest.mark.vcr
def test_update_device_disable_snmp():
    r1 = ise.update_device(name=device["new_name"], disable_snmp=True)

    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_snmp_settings_ro():
    r1 = ise.update_device(
        name=device["new_name"],
        snmp_ro="new-snmpcommunity",
    )
    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_snmp_settings_version():
    r1 = ise.update_device(
        name=device["new_name"],
        snmp_version="ONE",
    )
    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_snmp_settings_link_trap_query():
    r1 = ise.update_device(
        name=device["new_name"],
        snmp_link_trap_query="false",
    )
    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_snmp_settings_mac_trap_query():
    r1 = ise.update_device(
        name=device["new_name"],
        snmp_mac_trap_query="false",
    )
    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_snmp_settings_service_node():
    r1 = ise.update_device(
        name=device["new_name"],
        snmp_originating_policy_services_node=None,
    )
    assert r1["success"] is True
    r2 = ise.update_device(
        name=device["new_name"],
        snmp_originating_policy_services_node="Auto",
    )
    assert r2["success"] is True


# @pytest.mark.vcr
def test_update_device_snmp_settings_pollin_interval():
    r1 = ise.update_device(
        name=device["new_name"],
        snmp_polling_interval="3601",
    )
    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_snmp_settings_pollin_interval():
    r1 = ise.update_device(
        name=device["new_name"],
        snmp_polling_interval="3601",
    )
    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_dev_group():
    r0 = ise.add_device_group(
        name="changetotestgroup#changetotestgroup",
        description="temporary changeto testgroup",
    )
    r1 = ise.update_device(
        name=device["new_name"],
        dev_group="changetotestgroup#changetotestgroup",
    )
    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_dev_location():
    r1 = ise.update_device(
        name=device["new_name"],
        dev_location="Location#All Locations",
    )
    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_dev_type():
    r1 = ise.update_device(
        name=device["new_name"],
        dev_type="Device Type#All Device Types",
    )
    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_dev_ipsec():
    r1 = ise.update_device(
        name=device["new_name"],
        dev_ipsec="IPSEC#Is IPSEC Device#Yes",
    )
    assert r1["success"] is True


# @pytest.mark.vcr
def test_update_device_with_payload():
    r1 = ise.update_device(
        name=device["new_name"], device_payload=updated_device_payload
    )
    assert r1["success"] is True
    # cleanup
    ise.delete_device(device["new_name"])
    ise.delete_device(device["name"])
    ise.delete_device_group(name=device["dev_group"])
    ise.delete_device_group(name="changetotestgroup#changetotestgroup")


# @pytest.mark.vcr
def test_update_device_not_found():
    r1 = ise.update_device(name="NOT_FOUND", new_name=device["new_name"])
    assert r1["success"] is False
    assert r1["response"] == "NOT_FOUND not found"
    assert r1["error"] == 404


# @pytest.mark.vcr
def test_get_sgts():
    r1 = ise.get_sgts(size=1, page=1)
    assert r1["success"] is True


# @pytest.mark.vcr
def test_get_sgts_sgt_num():
    r1 = ise.get_sgts(sgtNum=9, size=1, page=1)
    assert r1["success"] is True


# @pytest.mark.vcr
def test_get_sgt():
    r1 = ise.get_sgt("Unknown")
    assert r1["success"] is True


# @pytest.mark.vcr
def test_add_sgt():
    r1 = ise.add_sgt(
        name="Python_Unit_Test",
        description="Unit Tests",
        value=trustsec["test_sgt_value"],
        return_object=True,
    )
    assert r1["success"] is True


def test_add_sgt_fail_to_large():
    r1 = ise.add_sgt(
        name="Python_Unit_Test 12345678901234567890123456798",
        description="Unit Tests",
        value=trustsec["test_sgt_value"],
        return_object=True,
    )
    assert r1["success"] is False


def test_add_sgt_fail_zero():
    r1 = ise.add_sgt(
        name="",
        description="Unit Tests",
        value="",
        return_object=True,
    )
    assert r1["success"] is False


# @pytest.mark.vcr
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


# @pytest.mark.vcr
def test_update_sgt_empty_name():
    id = 0
    r1 = ise.update_sgt(
        id,
        name="",
        description="Python Unit Tests",
        value=trustsec["test_sgt_value"],
    )
    assert r1["success"] is False
    assert "Invalid Security Group name" in r1["error"]


# @pytest.mark.vcr
def test_delete_sgt():
    res = ise.get_sgt("Test_Unit_Python")
    id = res["response"]["id"]
    r1 = ise.delete_sgt(id)
    assert r1["success"] is True


# @pytest.mark.vcr
def test_delete_sgt_null():
    r1 = ise.delete_sgt("9999999999")
    assert r1["success"] is False
    assert "not found" in r1["response"]
    assert r1["error"] == 404


# @pytest.mark.vcr
def test_get_sgacls():
    r1 = ise.get_sgacls(size=1, page=1)
    assert r1["success"] is True


# @pytest.mark.vcr
def test_get_sgacl():
    r1 = ise.get_sgacl("Permit IP")
    assert r1["success"] is True


# @pytest.mark.vcr
def test_get_sgacl():
    r1 = ise.get_sgacl("Permit IP")
    scal = r1["response"]["id"]
    r1 = ise.get_sgacl(scal)
    assert r1["success"] is True


# @pytest.mark.vcr
def test_add_sgacl():
    r1 = ise.add_sgacl(
        name="Python_Unit_Test",
        description="Unit Tests",
        ip_version="IPV4",
        acl_content=["permit ip"],
        return_object=True,
    )
    assert r1["success"] is True


# @pytest.mark.vcr
def test_add_sgacl_start_number():
    r1 = ise.add_sgacl(
        name="0Python_Unit_Test",
        description="Unit Tests",
        ip_version="IPV4",
        acl_content=["permit ip"],
        return_object=True,
    )
    assert r1["success"] is False


# @pytest.mark.vcr
def test_add_sgacl_space():
    r1 = ise.add_sgacl(
        name="Python Unit_Test",
        description="Unit Tests",
        ip_version="IPV4",
        acl_content=["permit ip"],
        return_object=True,
    )
    assert r1["success"] is False


# @pytest.mark.vcr
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


# @pytest.mark.vcr
def test_update_sgacl_empty_name():
    id = 0
    r1 = ise.update_sgacl(
        id,
        name="",
        description="Python Unit Tests",
        ip_version="IPV4",
        acl_content=["permit ip"],
    )
    assert r1["success"] is False
    assert "Invalid SGACL name" in r1["error"]


# @pytest.mark.vcr
def test_delete_sgacl():
    res = ise.get_sgacl("Test_Unit_Python")
    id = res["response"]["id"]
    r1 = ise.delete_sgacl(id)
    assert r1["success"] is True


# @pytest.mark.vcr
def test_delete_sgacl_fail():
    r1 = ise.delete_sgacl("999999999999999")
    assert r1["success"] is False
    assert "not found" in r1["response"]
    assert r1["error"] == 404


# @pytest.mark.vcr
def test_get_egressmatrixcells():
    r1 = ise.get_egressmatrixcells(size=1, page=1)
    assert r1["success"] is True


# @pytest.mark.vcr
def test_get_egressmatrixcell():
    r1 = ise.get_egressmatrixcell("Default egress rule")
    assert r1["success"] is True


# @pytest.mark.vcr
def test_get_egressmatrixcell_singe_oid():
    r1 = ise.get_egressmatrixcell("92c1a900-8c01-11e6-996c-525400b48521")
    assert r1["success"] is True


# #@pytest.mark.vcr
# def test_get_egressmatrixcell_not_found():
#    r1 = ise.get_egressmatrixcell("not found")
#    assert r1["success"] is False


# @pytest.mark.vcr
def test_add_egressmatrixcell():
    r1 = ise.add_egressmatrixcell(
        trustsec["emc_source_sgt"],
        trustsec["emc_dest_sgt"],
        "PERMIT_IP",
        description="Python Unit Tests",
        return_object=True,
    )
    assert r1["success"] is True


# @pytest.mark.vcr
def test_add_egressmatrixcell_duplicate():
    r1 = ise.add_egressmatrixcell(
        trustsec["emc_source_sgt"],
        trustsec["emc_dest_sgt"],
        "PERMIT_IP",
        description="Python Unit Tests",
        return_object=True,
    )
    assert r1["success"] is False
    assert "already a policy present" in r1["error"]


# @pytest.mark.vcr
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


# @pytest.mark.vcr
def test_delete_egressmatrixcell():
    res = ise.get_egressmatrixcell("Test_Unit_Python")
    id = res["response"]["id"]
    r1 = ise.delete_egressmatrixcell(id)
    assert r1["success"] is True


# @pytest.mark.vcr
def test_delete_egressmatrixcell_not_found():
    r1 = ise.delete_egressmatrixcell(9999999999999999)
    assert r1["success"] is False
    assert "not found" in r1["response"]
    assert r1["error"] == 404


# @pytest.mark.vcr
def test_add_egressmatrixcell_no_celldata():
    r1 = ise.add_egressmatrixcell(
        trustsec["emc_source_sgt"],
        trustsec["emc_dest_sgt"],
        "NONE",
        description="Python Unit Tests",
        return_object=True,
    )
    assert r1["success"] is False
    assert "You must specify one or more acls as a list" in r1["error"]


# @pytest.mark.vcr
def test_add_egressmatrixcell_list_fail():
    r1 = ise.add_egressmatrixcell(
        trustsec["emc_source_sgt"],
        trustsec["emc_dest_sgt"],
        "PERMIT_IP",
        ["92919850-8c01-11e6-996c-525400b48521", "Permit IP"],
        description="Python Unit Tests",
        return_object=True,
    )
    assert r1["success"] is False
    assert "Only one Catch All Rule SGACL can exsits" in r1["response"]
    assert r1["error"] == 400
