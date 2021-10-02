# This file will be fixed with pytest or unittest.
# But untill then this will work as a crude non-automagic testbed. // Falk

import sys

sys.path.append("./")

from pyiseers import ERS  # noqa E402
from pprint import pprint  # noqa E402
from config import (  # noqa E402
    uri_list,
    endpoint,
    endpoint_group,
    user,
    identity_group,
    device,
    device_group,
    trustsec,
    device_payload,
)


def test_groups():
    groups = ise.get_endpoint_groups()["response"]
    pprint(groups)

    group = ise.get_endpoint_group("Juniper-Device")["response"]
    pprint(group)


def add_endpoint(endpoint):
    test = ise.add_endpoint(
        endpoint["name"], endpoint["mac"], endpoint["group-id"]
    )  # noqa: E501
    if test["error"]:
        print(test["response"])
    else:
        print("add_endpoint » OK")


def get_endpoints():
    test = ise.get_endpoints(size=100, page=1)
    if test["error"]:
        print(test["response"])
    else:
        print("get_endpoints » OK")


def get_endpoint(endpoint):
    test = ise.get_endpoint(endpoint["mac"])
    if test["error"]:
        print(test["response"])
    else:
        print("get_endpoint » OK")


def delete_endpoint(endpoint):
    test = ise.delete_endpoint(endpoint["mac"])
    if test["error"]:
        print(test["response"])
    else:
        print("delete_endpoint » OK")


def get_endpoint_groups(size):
    test = ise.get_endpoint_groups(size=100, page=1)
    if test["error"]:
        print(test["response"])
    else:
        print("get_endpoint_groups » OK")


def get_endpoint_group(endpoint_group):
    test = ise.get_endpoint_group(endpoint_group["name"])
    if test["error"]:
        print(test["response"])
    else:
        print("get_endpoint_group » OK")


def get_identity_groups():
    test = ise.get_identity_groups(size=100, page=1)
    if test["error"]:
        print(test["response"])
    else:
        print("get_identity_groups » OK")


def get_identity_group(identity_group):
    test = ise.get_identity_group(identity_group["name"])
    if test["error"]:
        print(test["response"])
    else:
        print("get_identity_group » OK")

    identity_group_id = test["response"]["id"]

    return identity_group_id


def add_user(user, identity_group_id):
    test = ise.add_user(
        user_id=user["user_id"],
        password=user["password"],
        user_group_oid=identity_group_id,
        enable=user["enable"],
        first_name=user["first_name"],
        last_name=user["last_name"],
    )
    if test["error"]:
        print(test["response"])
    else:
        print("add_user » OK")


def get_users():
    test = ise.get_users(size=100, page=1)
    if test["error"]:
        print(test["response"])
    else:
        print("get_users » OK")


def get_user(user):
    test = ise.get_user(user["user_id"])
    if test["error"]:
        print(test["response"])
    else:
        print("get_user » OK")


def delete_user(user):
    test = ise.delete_user(user["user_id"])
    if test["error"]:
        print(test["response"])
    else:
        print("delete_user » OK")


def add_device_group(device_group):
    test = ise.add_device_group(
        name=device_group["name"], description=device_group["description"]
    )
    if test["error"]:
        print(test["response"])
    else:
        print("add_device_group » OK")


def get_device_groups():
    test = ise.get_device_groups(size=100, page=1)
    if test["error"]:
        print(test["response"])
    else:
        print("get_device_groups » OK")
    device_group = test["response"][0][1]

    return device_group


def get_device_group_from_name():
    test = ise.get_device_group(name="Python")
    if test["error"]:
        print(test["response"])
    else:
        print("get_device_group_from_name » OK")
    device_group_oid = test["response"]["id"]

    return device_group_oid


def get_device_group(device_group_id):
    test = ise.get_device_group(device_group_id)
    if test["error"]:
        print(test["response"])
    else:
        print("get_device_group » OK")


def update_device_group(device_group_id):
    test = ise.update_device_group(
        device_group_oid=device_group_id,
        name="Device Type#All Device Types#Updated Device Type",
        description="Update Description",
    )
    if test["error"]:
        print(test["response"])
    else:
        print("update_device_group » OK")


def delete_device_group():
    test = ise.delete_device_group(
        name="Device Type#All Device Types#Updated Device Type"
    )
    if test["error"]:
        print(test["response"])
    else:
        print("delete_device_group » OK")


def add_device(device):
    test = ise.add_device(
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
    if test["error"]:
        print(test["response"])
    else:
        print("add_device » OK")


def update_device(device):
    test = ise.update_device(name=device["name"], new_name=device["new_name"])
    if test["error"]:
        print(test["response"])
    else:
        print("update_device » OK")


def add_device_payload(device_payload):
    test = ise.add_device(device_payload=device_payload)
    if test["error"]:
        print(test["response"])
    else:
        print("add_device_payload » OK")


def get_devices():
    test_get = ise.get_devices(size=100, page=1)
    if test_get["error"]:
        print(test_get["response"])
    else:
        print("get_devices » OK")


def get_device(device):
    test = ise.get_device(device["name"])
    if test["error"]:
        print(test["response"])
    else:
        print("get_device » OK")


def get_updated_device(device):
    test = ise.get_device(device["new_name"])
    if test["error"]:
        print(test["response"])
    else:
        print("get_device » OK")


def delete_device(device):
    test = ise.delete_device(device["name"])
    if test["error"]:
        print(test["response"])
    else:
        print("delete_device » OK")


def delete_updated_device(device):
    test = ise.delete_device(device["new_name"])
    if test["error"]:
        print(test["response"])
    else:
        print("delete_updated_device » OK")


def get_sgts():
    test_get = ise.get_sgts(size=100, page=1)
    if test_get["error"]:
        print(test_get["response"])
    else:
        print("get_sgts » OK")


def get_sgt(name):
    test = ise.get_sgt(name)
    if test["error"]:
        print(test["response"])
    else:
        print("get_sgt » OK")


def add_sgt(trustsec):
    test = ise.add_sgt(
        name="Python_Unit_Test",
        description="Unit Tests",
        value=trustsec["test_sgt_value"],
        return_object=True,
    )
    if test["error"]:
        print(test["response"])
    else:
        print("add_sgt » OK")
    return test["response"]["id"]


def update_sgt(id, trustsec):
    test = ise.update_sgt(
        id,
        name="Test_Unit_Python",
        description="Python Unit Tests",
        value=trustsec["test_sgt_value"],
    )
    if test["error"]:
        print(test["response"])
    else:
        print("update_sgt » OK")


def delete_sgt(id):
    test = ise.delete_sgt(id)
    if test["error"]:
        print(test["response"])
    else:
        print("delete_sgt » OK")


def get_sgacls():
    test_get = ise.get_sgacls(size=100, page=1)
    if test_get["error"]:
        print(test_get["response"])
    else:
        print("get_sgacls » OK")


def get_sgacl(name):
    test = ise.get_sgacl(name)
    if test["error"]:
        print(test["response"])
    else:
        print("get_sgacl » OK")


def add_sgacl(trustsec):
    test = ise.add_sgacl(
        name="Python_Unit_Test",
        description="Unit Tests",
        ip_version="IPV4",
        acl_content=["permit ip"],
        return_object=True,
    )
    if test["error"]:
        print(test["response"])
    else:
        print("add_sgacl » OK")
    return test["response"]["id"]


def update_sgacl(id, trustsec):
    test = ise.update_sgacl(
        id,
        name="Test_Unit_Python",
        description="Python Unit Tests",
        ip_version="IPV4",
        acl_content=["permit ip"],
    )
    if test["error"]:
        print(test["response"])
    else:
        print("update_sgacl » OK")


def delete_sgacl(id):
    test = ise.delete_sgacl(id)
    if test["error"]:
        print(test["response"])
    else:
        print("delete_sgacl » OK")


def get_emcs():
    test_get = ise.get_egressmatrixcells(size=100, page=1)
    if test_get["error"]:
        print(test_get["response"])
    else:
        print("get_egressmatrixcells » OK")


def get_emc(name):
    test = ise.get_egressmatrixcell(name)
    if test["error"]:
        print(test["response"])
    else:
        print("get_egressmatrixcell » OK")


def add_emc(trustsec):
    test = ise.add_egressmatrixcell(
        trustsec["emc_source_sgt"],
        trustsec["emc_dest_sgt"],
        "PERMIT_IP",
        return_object=True,
    )
    if test["error"]:
        print(test["response"])
    else:
        print("add_egressmatrixcell » OK")
    return test["response"]["id"]


def update_emc(id, trustsec):
    test = ise.update_egressmatrixcell(
        id,
        trustsec["emc_source_sgt"],
        trustsec["emc_dest_sgt"],
        "NONE",
        description="Python Unit Tests",
        acls=[trustsec["test_assign_acl"]],
    )
    if test["error"]:
        print(test["response"])
    else:
        print("update_egressmatrixcell » OK")


def delete_emc(id):
    test = ise.delete_egressmatrixcell(id)
    if test["error"]:
        print(test["response"])
    else:
        print("delete_egressmatrixcell » OK")


if __name__ == "__main__":
    for uri in uri_list:
        ise = ERS(
            ise_node=uri["ise_node"],
            ers_user=uri["ers_user"],
            ers_pass=uri["ers_pass"],
            verify=False,
            disable_warnings=True,
            timeout=15,
            use_csrf=uri["use_csrf"],
        )

        print(f"Testing {ise.ise_node}")

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

        # Device group
        add_device_group(device_group)
        get_device_groups()
        device_group_id = get_device_group_from_name()
        get_device_group(device_group_id)
        update_device_group(device_group_id)
        delete_device_group()

        # Device tests
        add_device(device)
        get_devices()
        get_device(device)
        delete_device(device)
        add_device_payload(device_payload)
        get_device(device)
        update_device(device)
        get_updated_device(device)
        delete_updated_device(device)
        #  get_object()  # TODO

        # TrustSec SGT tests
        get_sgts()
        get_sgt("Unknown")
        sgtid = add_sgt(trustsec)
        update_sgt(sgtid, trustsec)
        delete_sgt(sgtid)

        # TrustSec SGACL tests
        get_sgacls()
        get_sgacl("Permit IP")
        sgaclid = add_sgacl(trustsec)
        update_sgacl(sgaclid, trustsec)
        delete_sgacl(sgaclid)

        # TrustSec Egress Matrix Cell (Policy) tests
        get_emcs()
        get_emc("Default egress rule")
        emcid = add_emc(trustsec)
        update_emc(emcid, trustsec)
        delete_emc(emcid)
