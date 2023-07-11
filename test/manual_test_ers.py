# I use this file often when trying out new functions and debugging with vscode.
# This file will be fixed with pytest or unittest.
# But untill then this will work as a crude non-automagic testbed. // Falk

import sys

sys.path.append("./pyise_ers/")

from pprint import pprint  # noqa E402

from config import (  # noqa E402
    device,
    device_group,
    device_payload,
    endpoint,
    endpoint_group,
    identity_group,
    trustsec,
    uri,
    user,
    debug,
)

from pyiseers import ERS  # noqa E402


def test_groups():
    groups = ise.get_endpoint_groups()["response"]
    pprint(groups)

    group = ise.get_endpoint_group("Juniper-Device")["response"]
    pprint(group)


def add_endpoint(endpoint):
    test = ise.add_endpoint(
        endpoint["name"], endpoint["mac"], endpoint["group-id"]
    )  # noqa: E501
    if debug:
       print(f"add_endpoint » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("add_endpoint » OK")


def get_endpoints():
    test = ise.get_endpoints(size=100, page=1)
    if debug:
       print(f"get_endpoints » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_endpoints » OK")


def get_endpoint(endpoint):
    test = ise.get_endpoint(endpoint["mac"])
    if debug:
       print(f"get_endpoint » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_endpoint » OK")


def delete_endpoint(endpoint):
    test = ise.delete_endpoint(endpoint["mac"])
    if debug:
       print(f"delete_endpoint » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("delete_endpoint » OK")


def get_endpoint_groups(size):
    test = ise.get_endpoint_groups(size=100, page=1)
    if debug:
       print(f"get_endpoint_groups » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_endpoint_groups » OK")


def add_endpoint_group(endpoint_group):
    test = ise.add_endpoint_group(endpoint_group["name"], endpoint_group["description"])
    if debug:
       print(f"add_endpoint_group » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("add_endpoint_group » OK")


def delete_endpoint_group(endpoint_group):
    r1 = ise.get_endpoint_group(endpoint_group["name"])
    test = ise.delete_endpoint_group(r1["response"]["id"])
    if debug:
       print(f"delete_endpoint_group » {str(test)}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("delete_endpoint_group » OK")


def get_endpoint_group(endpoint_group):
    test = ise.get_endpoint_group(endpoint_group["name"])
    if debug:
       print(f"get_endpoint_group » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_endpoint_group » OK")


def get_identity_groups():
    test = ise.get_identity_groups(size=100, page=1)
    if debug:
       print(f"get_identity_groups » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_identity_groups » OK")


def get_identity_group(identity_group):
    test = ise.get_identity_group(identity_group["name"])
    if debug:
       print(f"get_identity_group » {test}")
    else:
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
        email=user["email"],
    )
    if debug:
       print(f"add_user » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("add_user » OK")


def get_users():
    test = ise.get_users(size=100, page=1)
    if debug:
       print(f"get_users » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_users » OK")


def get_user(user):
    test = ise.get_user(user["user_id"])
    if debug:
       print(f"get_user » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_user » OK")


def get_user_by_email(user):
    test = ise.get_user_by_email(user["email"])
    if debug:
       print(f"get_user_by_email » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_user_by_email » OK")


def delete_user(user):
    test = ise.delete_user(user["user_id"])
    if debug:
       print(f"delete_user » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("delete_user » OK")


def get_admin_user(admin_user):
    test = ise.get_admin_user(admin_user)
    if debug:
       print(f"get_admin_user » {test}")
    else:
        if test["error"]:
            print(test["error"])
        else:
            print("get_admin_user » OK")


def add_device_group(device_group):
    test = ise.add_device_group(
        name=device_group["name"], description=device_group["description"]
    )
    if debug:
       print(f"add_device_group »{test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("add_device_group » OK")


def get_device_groups():
    test = ise.get_device_groups(size=100, page=1)
    if debug:
       print(f"get_device_groups » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_device_groups » OK")
    device_group = test["response"][0][1]

    return device_group


def get_device_groups_from_filter():
    test = ise.get_device_groups(size=100, page=1, filter="description.CONTAINS.sssPython")
    if not debug:
       print(f"get_device_groups_from_filter » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_device_groups_from_filter » OK")
    device_group = test["response"][0][1]

    return device_group


def get_device_group_from_name():
    test = ise.get_device_group(name="Python")
    if debug:
       print(f"get_device_group_from_name » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_device_group_from_name » OK")
    device_group_oid = test["response"]["id"]

    return device_group_oid


def get_device_group(device_group_id):
    test = ise.get_device_group(device_group_id)
    if debug:
       print(f"get_device_group » {test}")
    else:
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
    if debug:
       print(f"update_device_group » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("update_device_group » OK")


def delete_device_group():
    # r1 = ise.get_device_group(name="Device Type#All Device Types#Updated Device Type")
    test = ise.delete_device_group(
        name="Device Type#All Device Types#Updated Device Type"
    )
    if debug:
       print(f"delete_device_group » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("delete_device_group » OK")


def add_device(device):
    r1 = ise.add_device_group(
        name=device["dev_group"], description="temporary testgroup"
    )

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
    if debug:
       print(f"add_device » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("add_device » OK")

    cleanup = ise.delete_device_group(name=device["dev_group"])
    if debug:
       print(f"{cleanup}")


def add_device_multi_ip(device):
    r1 = ise.add_device_group(
        name=device["dev_group"], description="temporary testgroup"
    )

    test = ise.add_device(
        name=device["name_mip"],
        ip_address=device["ip_addresses"],
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
    if debug:
       print(f"add_device_multi_ip » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("add_device_multi_ip » OK")

    cleanup = ise.delete_device(device["name_mip"])
    if debug:
       print(f"{cleanup}")
    cleanup = ise.delete_device_group(name=device["dev_group"])
    if debug:
       print(f"{cleanup}")


def update_device_name(device):
    test = ise.update_device(name=device["name"], new_name=device["new_name"])
    if debug:
       print(f"update_device » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("update_device » OK")


def update_device_radius_key(device):
    test = ise.update_device(name=device["new_name"], radius_key="new-test-radius-key")
    if debug:
       print(f"update_device_radius_key » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("update_device_radius_key » OK")


def add_device_payload(device_payload):
    test = ise.add_device(device_payload=device_payload)
    if debug:
       print(f"add_device_payload » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("add_device_payload » OK")


def get_devices():
    test = ise.get_devices(size=100, page=1)
    if debug:
       print(f"get_devices » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_devices » OK")


def get_device(device):
    test = ise.get_device(device["name"])
    if debug:
       print(f"get_device » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_device » OK")


def get_updated_device(device):
    test = ise.get_device(device["new_name"])
    if debug:
       print(f"get_device » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_device » OK")


def delete_device(device):
    test = ise.delete_device(device["name"])
    if debug:
       print(f"delete_device » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("delete_device » OK")


def delete_updated_device(device):
    test = ise.delete_device(device["new_name"])
    if debug:
       print(f"delete_updated_device » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("delete_updated_device » OK")


def get_sgts():
    test = ise.get_sgts(size=100, page=1)
    if debug:
       print(f"get_sgts » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_sgts » OK")


def get_sgt(name):
    test = ise.get_sgt(name)
    if debug:
       print(f"get_sgt » {test}")
    else:
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
    if debug:
       print(f"add_sgt » {test}")
    else:
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
    if debug:
       print(f"update_sgt » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("update_sgt » OK")


def delete_sgt(id):
    test = ise.delete_sgt(id)
    if debug:
       print(f"delete_sgt » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("delete_sgt » OK")


def get_sgacls():
    test = ise.get_sgacls(size=100, page=1)
    if debug:
       print(f"get_sgacls » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_sgacls » OK")


def get_sgacl(name):
    test = ise.get_sgacl(name)
    if debug:
       print(f"get_sgacl » {test}")
    else:
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
    if debug:
       print(f"add_sgacl » {test}")
    else:
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
    if debug:
       print(f"update_sgacl » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("update_sgacl » OK")


def delete_sgacl(id):
    test = ise.delete_sgacl(id)
    if debug:
       print(f"delete_sgacl »  {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("delete_sgacl » OK")


def get_emcs():
    test = ise.get_egressmatrixcells(size=100, page=1)
    if debug:
       print(f"get_egressmatrixcells » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("get_egressmatrixcells » OK")


def get_emc(name):
    test = ise.get_egressmatrixcell(name)
    if debug:
       print(f"get_egressmatrixcell » {test}")
    else:
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
    if debug:
       print(f"add_egressmatrixcell » {test}")
    else:
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
    if debug:
       print(f"update_egressmatrixcell »  {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("update_egressmatrixcell » OK")


def delete_emc(id):
    test = ise.delete_egressmatrixcell(id)
    if debug:
       print(f"delete_egressmatrixcell » {test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print("delete_egressmatrixcell » OK")


if __name__ == "__main__":
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

    #
    # Endpoint tests
    add_endpoint(endpoint)
    get_endpoints()
    get_endpoint(endpoint)
    delete_endpoint(endpoint)

    # EndpointGroup tests
    add_endpoint_group(endpoint_group)
    get_endpoint_groups(21)
    get_endpoint_group(endpoint_group)
    delete_endpoint_group(endpoint_group)

    # User tests
    get_identity_groups()
    identity_group_id = get_identity_group(identity_group)
    add_user(user, identity_group_id)
    get_users()
    get_user(user)
    get_user_by_email(user)
    delete_user(user)

    # Admin user tests
    get_admin_user("admin")

    # Device group
    add_device_group(device_group)
    get_device_groups()
    get_device_groups_from_filter()
    device_group_id = get_device_group_from_name()
    get_device_group(device_group_id)
    update_device_group(device_group_id)
    delete_device_group()

    # Device tests
    add_device(device)
    add_device_multi_ip(device)
    get_devices()
    get_device(device)
    delete_device(device)
    add_device_payload(device_payload)
    get_device(device)
    update_device_name(device)
    update_device_radius_key(device)

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
