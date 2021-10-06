# This file will be fixed with pytest or unittest.
# But untill then this will work as a crude non-automagic testbed. // Falk

import sys
from config import endpoint
sys.path.append("./")

from pyiseers import ERS  # noqa E402
from pprint import pprint  # noqa E402

uri = {
    "ise_node": "192.168.1.30",
    "ers_user": "ers-users",
    "ers_pass": "Password30",
    "use_csrf": False,
}

ise = ERS(
    ise_node=uri["ise_node"],
    ers_user=uri["ers_user"],
    ers_pass=uri["ers_pass"],
    verify=False,
    disable_warnings=True,
    timeout=15,
    use_csrf=uri["use_csrf"],
)


device = {
    "name": "test-name",
    "new_name": "new-test-name",
}

device_payload = {
    "name": "test-name",
    "description": "test-description",
    "profileName": "Cisco",
    "coaPort": "1700",
    "NetworkDeviceIPList": [
        {
            "ipaddress": "1.1.1.1",
            "mask": "32",
        }
    ],
    "NetworkDeviceGroupList": [
        "Device Type#All Device Types",
        "Location#All Locations",
        "IPSEC#Is IPSEC Device#No",
    ],
}


if __name__ == "__main__":

    #r0 = ise.get_device_groups()
    #print(r0)

    r1 = ise.get_endpoint_group("NO GROUP THAT EXISTS")  
    print(r1)

    # r1 = ise.add_device(device_payload=device_payload)
    # pprint(device_payload)

    # r2 = ise.update_device(name=device["name"], new_name=device["new_name"])
    # print("\n------------ First device_update ------------\n")
    # pprint(r2["response"])
    # r3 = ise.update_device(name=device["new_name"], new_name=device["name"])
    # print("\n------------ Second device_update ------------\n")
    # pprint(r3["response"])
    # r4 = ise.update_device(name=device["name"], new_name=device["new_name"])
    # print("\n------------ Third device_update ------------\n")
    # pprint(r4["response"])
    # r5 = ise.delete_device(device["new_name"])
#

## Create ISSUES:
# if wrong auth in 3.x only a 404 noth an error
# Wrong mac address "raoise problem"