# Some testing stuff, please do not run in production

import sys
import argparse

sys.path.append("./pyise_ers/")

from pprint import pprint  # noqa E402
from random import randint

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


def random_mac(separator_char=':', separator_spacing=2):
    """
    Generate random macaddress
    From » https://kyletk.com/post/27/python-generate-random-mac-address
    """
    unseparated_mac = ''.join([hex(randint(0, 255))[2:].zfill(2) for _ in range(6)])
    return f'{separator_char}'.join(unseparated_mac[i:i + separator_spacing] for i in range(0, len(unseparated_mac), separator_spacing))



def add_endpoint(endpoint, i, total):
    macaddress = random_mac()
    print(macaddress)
    test = ise.add_endpoint(
        endpoint["name"], macaddress, endpoint["group-id"]
    )  # noqa: E501
    if debug:
       print(f"{test}")
    else:
        if test["error"]:
            print(test["response"])
        else:
            print(f"add_endpoint » #{i+1} of {total}")

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

    parser = argparse.ArgumentParser(description="Generate and insert x number of random macaddresses into you test ise")
    parser.add_argument("number", type=int, help="Number of macadresses to add")


    args = parser.parse_args()

    print(f"Generate random entdpoints {ise.ise_node}")

    #
    # Endpoint tests
    for i in range(args.number):
        add_endpoint(endpoint, i, args.number)
    