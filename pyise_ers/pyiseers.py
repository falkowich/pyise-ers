"""Class to configure Cisco ISE via the ERS API."""
import json
import os
import re
from datetime import datetime, timedelta
from urllib.parse import quote

import requests
from furl import furl

base_dir = os.path.dirname(__file__)


class InvalidMacAddress(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class ERS(object):
    def __init__(
        self,
        ise_node,
        ers_user,
        ers_pass,
        verify=False,
        disable_warnings=False,
        use_csrf=False,
        timeout=2,
        protocol="https",
    ):
        """
        Class to interact with Cisco ISE via the ERS API.

        :param ise_node: IP Address of the primary admin ISE node
        :param ers_user: ERS username
        :param ers_pass: ERS password
        :param verify: Verify SSL cert
        :param disable_warnings: Disable requests warnings
        :param timeout: Query timeout
        """
        self.ise_node = ise_node
        self.user_name = ers_user
        self.user_pass = ers_pass
        self.protocol = protocol

        self.url_base = f"{self.protocol}://{self.ise_node}:9060/ers"
        self.ise = requests.sessions.Session()
        self.ise.auth = (self.user_name, self.user_pass)
        # http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification
        self.ise.verify = verify
        self.disable_warnings = disable_warnings
        self.use_csrf = use_csrf
        self.csrf = None
        self.csrf_expires = None
        self.timeout = timeout
        self.ise.headers.update({"Connection": "keep_alive"})

        if self.disable_warnings:
            requests.packages.urllib3.disable_warnings()

    @staticmethod
    def _mac_test(mac):
        """
        Test for valid mac address.

        :param mac: MAC address in the form of AA:BB:CC:00:11:22
        :return: True/False
        """
        if (
            mac
            and re.search(r"([0-9A-F]{2}[:]){5}([0-9A-F]){2}", mac.upper()) is not None
        ):
            return True
        else:
            return False

    @staticmethod
    def _sgt_name_test(name):
        """
        Test for valid name.

        :param name: Name; must not be null, must be <= 32 char, alphanumeric + _ only.
        :return: True/False
        """
        if name and re.search(r"^[a-zA-Z0-9_]*$", name) is not None and len(name) <= 32:
            return True
        else:
            return False

    @staticmethod
    def _sgacl_name_test(name):
        """
        Test for valid name.

        :param name: Name; must start with letter; alphanumeric + _ only.
        :return: True/False
        """
        if name and re.search(r"^[a-zA-Z][a-zA-Z0-9_]*$", name) is not None:
            return True
        else:
            return False

    @staticmethod
    def _oid_test(id):
        """
        Test for a valid OID
        :param id: OID in the form of abcd1234-ef56-7890-abcd1234ef56
        :return: True/False
        """
        if id and re.match(r"^([a-f0-9]{8}-([a-f0-9]{4}-){3}[a-z0-9]{12})$", id):
            return True
        else:
            return False

    @staticmethod
    def _pass_ersresponse(result, resp):
        try:
            rj = resp.json()
            if "SearchResult" in rj:
                result["response"] = None
            elif rj["ERSResponse"]["messages"][0].get("title"):
                result["response"] = rj["ERSResponse"]["messages"][0]["title"]
            else:
                # No "title" in message as of ISE 3.1
                # https://community.cisco.com/t5/network-access-control/ise-3-1-ers-delete-ers-config-sgacl-500-internal-server-error/td-p/4829897
                result["response"] = rj["ERSResponse"]["messages"][0]["code"]
                result["response"] = f"Undefined {result['response']} error"

            result["error"] = resp.status_code
            return result
        except ValueError:
            if "<title>HTTP Status 401 – Unauthorized</title>" in resp.text:
                result["response"] = "Unauthorized"
                result["error"] = resp.status_code
                return result
            else:
                result["error"] = resp.status_code
                return result

    def _request(self, url, method="get", data=None):
        if self.use_csrf:
            if (
                not self.csrf_expires
                or not self.csrf
                or datetime.utcfromtimestamp(0) > self.csrf_expires
            ):
                self.ise.headers.update(
                    {
                        "ACCEPT": "application/json",
                        "Content-Type": "application/json",
                        "X-CSRF-TOKEN": "fetch",
                    }
                )

                resp = self.ise.get(
                    f"{self.url_base}/config/deploymentinfo/versioninfo",
                    timeout=self.timeout,
                )
                self.csrf = resp.headers["X-CSRF-Token"]
                self.csrf_expires = datetime.utcfromtimestamp(0) + timedelta(seconds=60)

            self.ise.headers.update(
                {
                    "ACCEPT": "application/json",
                    "Content-Type": "application/json",
                    "X-CSRF-TOKEN": self.csrf,
                }
            )

            req = self.ise.request(method, url, data=data, timeout=self.timeout)
        else:
            req = self.ise.request(method, url, data=data, timeout=self.timeout)

        return req

    def _get_groups(self, url, filter: str = None):
        """
        Get generic group lists.

        :param url: Base URL for requesting lists
        :return: result dictionary
        """
        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        self.ise.headers.update(
            {"Accept": "application/json", "Content-Type": "application/json"}
        )

        f = furl(url)
        # Max resources per page cannot be more then 100 resources.
        f.args["size"] = 100
        # TODO add filter valication
        if filter:
            f.args["filter"] = filter

        resp = self.ise.get(f.url, timeout=self.timeout)

        if resp.status_code == 200:
            result["success"] = True
            result["total"] = resp.json()["SearchResult"]["total"]
            result["response"] = []
            for page in range(1, int((result["total"] / f.args["size"] + 1) + 1)):
                f.args["page"] = page
                resp = self.ise.get(f.url, timeout=self.timeout)
                if resp.status_code == 200:
                    result["response"] += [
                        (i["name"], i["id"], i["description"])
                        for i in resp.json()["SearchResult"]["resources"]
                    ]
            return result

        else:
            return ERS._pass_ersresponse(result, resp)

    def _get_objects(self, url, filter: str = None):
        """
        Generic method for requesting objects lists.

        :param url: Base URL for requesting lists
        :param filter: argument side of a ERS filter string. Default: None
        :return: result dictionary
        """
        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        self.ise.headers.update(
            {"Accept": "application/json", "Content-Type": "application/json"}
        )

        f = furl(url)
        # Max resources per page cannot be more then 100 resources.
        f.args["size"] = 100
        # TODO add filter valication
        if filter:
            f.args["filter"] = filter

        resp = self.ise.get(f.url, timeout=self.timeout)

        if resp.status_code == 200:
            json_res = resp.json()["SearchResult"]

            if int(json_res["total"]) >= 1:
                result["success"] = True
                result["total"] = json_res["total"]
                result["response"] = []
                for page in range(1, int((result["total"] / f.args["size"] + 1) + 1)):
                    f.args["page"] = page
                    resp = self.ise.get(f.url, timeout=self.timeout)
                    if resp.status_code == 200:
                        json_res = resp.json()["SearchResult"]
                        result["response"] += [
                            (i["name"], i["id"]) for i in json_res["resources"]
                        ]
                return result

            elif int(json_res["total"]) == 0:
                result["success"] = True
                result["response"] = []
                result["total"] = json_res["total"]
                return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_endpoint_groups(self):
        """
        Get all endpoint identity groups.

        :param size: Size of the number of identity groups before pagination starts
        :return: result dictionary
        """
        return self._get_groups(
            f"{self.url_base}/config/endpointgroup"
        )

    def get_endpoint_group(self, group):
        """
        Get endpoint identity group details.

        :param group: Name of the identity group
        :return: result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        # If it's a valid OID, perform a more direct GET-call
        if self._oid_test(group):
            result = self.get_object(
                f"{self.url_base}/config/endpointgroup", group, "EndPointGroup"
            )
            return result
        # If not valid OID, perform regular search
        else:
            resp = self.ise.get(
                f"{self.url_base}/config/endpointgroup?filter=name.EQ.{group}",
                timeout=self.timeout,
            )
            found_group = resp.json()

        if found_group["SearchResult"]["total"] == 1:
            result = self.get_object(
                f"{self.url_base}/config/endpointgroup",
                found_group["SearchResult"]["resources"][0]["id"],
                "EndPointGroup",
            )

            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def add_endpoint_group(self, name, description=""):
        """
        Add an endpoint group.
        :param name: Group name
        :param description: Group description
        :return: result dictionary
        """
        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        data = {
            "EndPointGroup": {
                "name": name,
                "description": description,
            }
        }

        resp = self._request(
            f"{self.url_base}/config/endpointgroup",
            method="post",
            data=json.dumps(data),
        )
        if resp.status_code == 201:
            result["success"] = True
            result["response"] = f"{name} Added Successfully"
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def delete_endpoint_group(self, id):
        """
        Deletes an endpoint group.
        :param id: Group ID
        :return: result dictionary
        """
        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )
        resp = self._request(
            f"{self.url_base}/config/endpointgroup/{id}",
            method="delete",
        )

        if resp.status_code == 204:
            result["success"] = True
            result["response"] = f"{id} Deleted Successfully"
            return result
        elif resp.status_code == 404:
            result["response"] = f"{id} not found"
            result["error"] = resp.status_code
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_endpoints(self, groupID=None):
        """
        Get all endpoints.

        :param groupID: List only endpoints in a specific GroupID. Default: None
        :return: result dictionary
        """
        if groupID:
            filter = f"groupId.EQ.{groupID}"
        else:
            filter = None

        return self._get_objects(
            f"{self.url_base}/config/endpoint",
            filter=filter
        )

    def get_sgts(self, sgtNum=None):
        """
        Get all Secure Group Tags.

        :param sgtNum: retrieve sgt configuration for given SGT Number
        :return: result dictionary
        """
        if sgtNum:
            filter = f"value.EQ.{sgtNum}"
        else:
            filter = None

        return self._get_objects(
            f"{self.url_base}/config/sgt",
            filter=filter
        )

    def get_sgt(self, sgt):
        """
        Get Secure Group Tag details.

        :param sgt: name or Object ID of the Secure Group Tag
        :return: result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        # If it's a valid OID, perform a more direct GET-call
        if self._oid_test(sgt):
            result = self.get_object(f"{self.url_base}/config/sgt", sgt, "Sgt")
            return result
        # If not valid OID, perform regular search
        else:
            if isinstance(sgt, int):
                resp = self.ise.get(
                    f"{self.url_base}/config/sgt?filter=value.EQ.{sgt}",
                    timeout=self.timeout,
                )
            else:
                resp = self.ise.get(
                    f"{self.url_base}/config/sgt?filter=name.EQ.{sgt}",
                    timeout=self.timeout,
                )
            found_group = resp.json()

        if found_group["SearchResult"]["total"] == 1:
            result = self.get_object(
                f"{self.url_base}/config/sgt",
                found_group["SearchResult"]["resources"][0]["id"],
                "Sgt",
            )

            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def add_sgt(
        self, name, description, value, propogate_to_apic=False, return_object=False
    ):
        """
        Add a SGT to TrustSec Components

        :param name: Name
        :param description: Description
        :param value: SGT Number
        :param propogate_to_apic: Specific to ACI
        :param return_object: Look up object after creation and return in response
        """
        is_valid = ERS._sgt_name_test(name)
        if not is_valid:
            result = {
                "success": False,
                "response": "",
                "error": f"{name}. Invalid Security Group name, name may not be null and longer than 32 characters and "
                "only contain the alphanumeric or underscore characters.",
            }
            return result
        else:
            self.ise.headers.update(
                {"ACCEPT": "application/json", "Content-Type": "application/json"}
            )

            result = {
                "success": False,
                "response": "",
                "error": "",
            }

            data = {
                "Sgt": {
                    "name": name,
                    "description": description,
                    "value": value,
                    "propogateToApic": propogate_to_apic,
                }
            }

            resp = self._request(
                f"{self.url_base}/config/sgt",
                method="post",
                data=json.dumps(data),
            )
            if resp.status_code == 201:
                result["success"] = True
                if return_object:
                    result["response"] = self.get_sgt(name)["response"]
                else:
                    result["response"] = f"{name} Added Successfully"
                return result
            else:
                return ERS._pass_ersresponse(result, resp)

    def update_sgt(
        self,
        sgt,
        name,
        description,
        value,
        propogate_to_apic=False,
        return_object=False,
    ):
        """
        Update SGT in TrustSec Components

        :param sgt: Object ID of sgt
        :param name: Name
        :param description: Description
        :param value: SGT Number
        :param propogate_to_apic: Specific to ACI
        :param return_object: Look up object after update and return in response
        """
        is_valid = ERS._sgt_name_test(name)
        if not is_valid:
            result = {
                "success": False,
                "response": "",
                "error": f"{name}. Invalid Security Group name, name may not be null and longer than 32 characters and "
                "only contain the alphanumeric or underscore characters.",
            }
            return result
        else:
            self.ise.headers.update(
                {"ACCEPT": "application/json", "Content-Type": "application/json"}
            )

            result = {
                "success": False,
                "response": "",
                "error": "",
            }

            data = {
                "Sgt": {
                    "name": name,
                    "description": description,
                    "value": value,
                    "propogateToApic": propogate_to_apic,
                }
            }

            resp = self._request(
                (f"{self.url_base}/config/sgt/{sgt}"),
                method="put",
                data=json.dumps(data),
            )
            if resp.status_code == 200:
                result["success"] = True
                if return_object:
                    result["response"] = self.get_sgt(sgt)["response"]
                else:
                    result["response"] = resp.json()
                return result
            else:
                return ERS._pass_ersresponse(result, resp)

    def delete_sgt(self, sgt):
        """
        Delete SGT in TrustSec Components

        :param sgt: Object ID of sgt
        :return: Result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        resp = self._request(f"{self.url_base}/config/sgt/{sgt}", method="delete")

        if resp.status_code == 204:
            result["success"] = True
            result["response"] = f"{sgt} Deleted Successfully"
            return result
        elif resp.status_code == 404:
            result["response"] = f"{sgt} not found"
            result["error"] = resp.status_code
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_sgacls(self):
        """
        Get all Secure Group ACLs.

        :param sgaclId: retrieve sgacl configuration for given SGACL Object ID
        :return: result dictionary
        """

        filter = None

        return self._get_objects(
            f"{self.url_base}/config/sgacl",
            filter=filter
        )

    def get_sgacl(self, sgacl):
        """
        Get Secure Group ACL details.

        :param sgacl: name or Object ID of the Secure Group ACL
        :return: result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        # If it's a valid OID, perform a more direct GET-call
        if self._oid_test(sgacl):
            result = self.get_object(f"{self.url_base}/config/sgacl", sgacl, "Sgacl")
            return result
        # If not valid OID, perform regular search
        else:
            resp = self.ise.get(
                f"{self.url_base}/config/sgacl?filter=name.EQ.{sgacl}",
                timeout=self.timeout,
            )
            found_group = resp.json()

        if found_group["SearchResult"]["total"] == 1:
            result = self.get_object(
                f"{self.url_base}/config/sgacl",
                found_group["SearchResult"]["resources"][0]["id"],
                "Sgacl",
            )

            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def add_sgacl(
        self, name, description, ip_version, acl_content, return_object=False
    ):
        """
        Add a SG ACL to TrustSec Components

        :param name: Name
        :param description: Description
        :param ip_version: IPV4, IPV6, or IP_AGNOSTIC
        :param acl_content: List of ACLs
        :param return_object: Look up object after creation and return in response
        """
        is_valid = ERS._sgacl_name_test(name)
        if not is_valid:
            result = {
                "success": False,
                "response": "",
                "error": f"{name}. Invalid SGACL name, name should start with a letter and can only contain the "
                "alphanumeric or underscore characters.",
            }
            return result
        else:
            self.ise.headers.update(
                {"ACCEPT": "application/json", "Content-Type": "application/json"}
            )

            result = {
                "success": False,
                "response": "",
                "error": "",
            }

            data = {
                "Sgacl": {
                    "name": name,
                    "description": description,
                    "ipVersion": ip_version,
                    "aclcontent": "\n".join(acl_content),
                }
            }

            resp = self._request(
                f"{self.url_base}/config/sgacl",
                method="post",
                data=json.dumps(data),
            )
            if resp.status_code == 201:
                result["success"] = True
                if return_object:
                    result["response"] = self.get_sgacl(name)["response"]
                else:
                    result["response"] = f"{name} Added Successfully"
                return result
            else:
                return ERS._pass_ersresponse(result, resp)

    def update_sgacl(
        self, sgacl, name, description, ip_version, acl_content, return_object=False
    ):
        """
        Update a SG ACL from TrustSec Components

        :param sgacl: Object ID of sgacl
        :param name: Name
        :param description: Description
        :param ip_version: IPV4, IPV6, or IP_AGNOSTIC
        :param acl_content: List of ACLs
        :param return_object: Look up object after creation and return in response
        """
        is_valid = ERS._sgacl_name_test(name)
        if not is_valid:
            result = {
                "success": False,
                "response": "",
                "error": f"{name}. Invalid SGACL name, name should start with a letter and can only contain the "
                "alphanumeric or underscore characters.",
            }
            return result
        else:
            self.ise.headers.update(
                {"ACCEPT": "application/json", "Content-Type": "application/json"}
            )

            result = {
                "success": False,
                "response": "",
                "error": "",
            }

            data = {
                "Sgacl": {
                    "name": name,
                    "description": description,
                    "ipVersion": ip_version,
                    "aclcontent": "\n".join(acl_content),
                }
            }

            resp = self._request(
                f"{self.url_base}/config/sgacl/{sgacl}",
                method="put",
                data=json.dumps(data),
            )
            if resp.status_code == 200:
                result["success"] = True
                if return_object:
                    result["response"] = self.get_sgacl(sgacl)["response"]
                else:
                    result["response"] = resp.json()
                return result
            else:
                return ERS._pass_ersresponse(result, resp)

    def delete_sgacl(self, sgacl):
        """
        Delete SGACL in TrustSec Components

        :param sgacl: Object ID of sgacl
        :return: Result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        resp = self._request(f"{self.url_base}/config/sgacl/{sgacl}", method="delete")

        if resp.status_code == 204:
            result["success"] = True
            result["response"] = f"{sgacl} Deleted Successfully"
            return result
        elif resp.status_code == 404:
            result["response"] = f"{sgacl} not found"
            result["error"] = resp.status_code
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_egressmatrixcells(self):
        """
        Get all TrustSec Egress Matrix Cells.

        :param emcId: retrieve policy configuration for given egress matrix cell Object ID
        :return: result dictionary
        """

        filter = None

        return self._get_objects(
            f"{self.url_base}/config/egressmatrixcell",
            filter=filter
        )

    def get_egressmatrixcell(self, emc, src_sgt=None, dst_sgt=None):
        """
        Get TrustSec Egress Matrix Cell Policy details.

        :param emc: name or Object ID of the TrustSec Egress Matrix Cell Policy
        :param src_sgt: name or Object ID of the Source SGT in the Policy
        :param src_sgt: name or Object ID of the Dest SGT in the Policy
        :return: result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        # If it's a valid OID, perform a more direct GET-call
        if self._oid_test(emc):
            result = self.get_object(
                f"{self.url_base}/config/egressmatrixcell",
                emc,
                "EgressMatrixCell",
            )
            return result
        # If not valid OID, perform regular search
        else:
            if emc:
                resp = self.ise.get(
                    f"{self.url_base}/config/egressmatrixcell?filter=description.EQ.{emc}",
                    timeout=self.timeout,
                )
                found_group = resp.json()
            elif src_sgt and dst_sgt:
                srcsgtval = self.get_sgt(src_sgt)["response"]["value"]
                dstsgtval = self.get_sgt(dst_sgt)["response"]["value"]
                resp = self.ise.get(
                    f"{self.url_base}/config/egressmatrixcell?filter=sgtSrcValue.EQ.{srcsgtval}&filter=sgtDstValue.EQ.{dstsgtval}",
                    timeout=self.timeout,
                )
                found_group = resp.json()
            else:
                return result

        if found_group["SearchResult"]["total"] == 1:
            result = self.get_object(
                f"{self.url_base}/config/egressmatrixcell",
                found_group["SearchResult"]["resources"][0]["id"],
                "EgressMatrixCell",
            )

            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def add_egressmatrixcell(
        self,
        source_sgt,
        destination_sgt,
        default_rule,
        acls=None,
        description=None,
        return_object=False,
    ):
        """
        Add TrustSec Egress Matrix Cell Policy.

        :param description: Description
        :param source_sgt: Source SGT name or Object ID
        :param destination_sgt: Destination SGT name or Object ID
        :param default_rule: "NONE", "PERMIT_IP", "DENY_IP"
        :param acls: list of SGACL Object IDs. Can be None.
        :param return_object: Look up object after creation and return in response
        """

        # ISE will actually allow you to post duplicate polices, so before we execute the post, double check to
        # make sure a policy doesn't already exist
        src_sgt = self.get_sgt(source_sgt)["response"].get("id", None)
        dst_sgt = self.get_sgt(destination_sgt)["response"].get("id", None)
        if src_sgt and dst_sgt:
            celldata = self.get_egressmatrixcell(
                None, src_sgt=src_sgt, dst_sgt=dst_sgt
            )["response"]
        else:
            celldata = None

        if celldata:
            result = {
                "success": False,
                "response": "",
                "error": "There is already a policy present for this source and destination. Please use update to make "
                "policy changes.",
            }
            return result
        elif default_rule == "NONE" and acls is None:
            result = {
                "success": False,
                "response": "",
                "error": "You must specify one or more acls as a list, or a default_rule; both cannot be blank",
            }
            return result
        else:
            self.ise.headers.update(
                {"ACCEPT": "application/json", "Content-Type": "application/json"}
            )

            result = {
                "success": False,
                "response": "",
                "error": "",
            }

            newacls = []
            if acls:
                for a in acls:
                    if self._oid_test(a):
                        newacls.append(a)
                    else:
                        newacl = self.get_sgacl(a)["response"].get("id", None)
                        if newacl:
                            newacls.append(newacl)

            data = {
                "EgressMatrixCell": {
                    "description": description,
                    "sourceSgtId": src_sgt,
                    "destinationSgtId": dst_sgt,
                    "defaultRule": default_rule,
                    "matrixCellStatus": "ENABLED",
                    "sgacls": newacls,
                }
            }

            resp = self._request(
                f"{self.url_base}/config/egressmatrixcell",
                method="post",
                data=json.dumps(data),
            )
            if resp.status_code == 201:
                result["success"] = True
                if return_object:
                    result["response"] = self.get_egressmatrixcell(
                        None, src_sgt=src_sgt, dst_sgt=dst_sgt
                    )["response"]
                else:
                    result["response"] = f"{description} Added Successfully"
                return result
            else:
                return ERS._pass_ersresponse(result, resp)

    def update_egressmatrixcell(
        self,
        emc,
        source_sgt,
        destination_sgt,
        default_rule,
        acls=None,
        description=None,
        return_object=False,
    ):
        """
        Update TrustSec Egress Matrix Cell Policy.

        :param emc: Object ID of egress matrix cell
        :param description: Description
        :param source_sgt: Source SGT name or Object ID
        :param destination_sgt: Destination SGT name or Object ID
        :param default_rule: "NONE", "PERMIT_IP", "DENY_IP"
        :param acls: list of SGACL Object IDs. Can be None.
        :param return_object: Look up object after creation and return in response
        """
        if not emc:
            result = {
                "success": False,
                "response": "",
                "error": "You must provide the egress matrix cell object id in order to update it.",
            }
            return result
        else:
            self.ise.headers.update(
                {"ACCEPT": "application/json", "Content-Type": "application/json"}
            )

            result = {
                "success": False,
                "response": "",
                "error": "",
            }

            newacls = []
            if acls:
                for a in acls:
                    if self._oid_test(a):
                        newacls.append(a)
                    else:
                        newacl = self.get_sgacl(a)["response"].get("id", None)
                        if newacl:
                            newacls.append(newacl)

            src_sgt = self.get_sgt(source_sgt)["response"]["id"]
            dst_sgt = self.get_sgt(destination_sgt)["response"]["id"]
            data = {
                "EgressMatrixCell": {
                    "id": emc,
                    "description": description,
                    "sourceSgtId": src_sgt,
                    "destinationSgtId": dst_sgt,
                    "defaultRule": default_rule,
                    "matrixCellStatus": "ENABLED",
                    "sgacls": newacls,
                }
            }

            resp = self._request(
                f"{self.url_base}/config/egressmatrixcell/{emc}",
                method="put",
                data=json.dumps(data),
            )
            if resp.status_code == 200:
                result["success"] = True
                if return_object:
                    result["response"] = self.get_egressmatrixcell(emc)["response"]
                else:
                    result["response"] = resp.json()
                return result
            else:
                return ERS._pass_ersresponse(result, resp)

    def delete_egressmatrixcell(self, emc):
        """
        Delete TrustSec Egress Matrix Cell Policy.

        :param emc: Object ID of egress matrix cell policy
        :return: Result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        resp = self._request(
            f"{self.url_base}/config/egressmatrixcell/{emc}",
            method="delete",
        )

        if resp.status_code == 204:
            result["success"] = True
            result["response"] = f"{emc} Deleted Successfully"
            return result
        elif resp.status_code == 404:
            result["response"] = f"{emc} not found"
            result["error"] = resp.status_code
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_object(self, url: str, objectid: str, objecttype: str):
        """
        Get generic object lists.

        :param url: Base URL for requesting lists
        :param objectid: ID retreved from previous search.
        :param objecttype: "ERSEndPoint", etc...
        :return: result dictionary
        """
        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        self.ise.headers.update(
            {"Accept": "application/json", "Content-Type": "application/json"}
        )

        f = furl(url)
        f.path /= objectid
        resp = self.ise.get(f.url, timeout=self.timeout)

        if resp.status_code == 200:
            result["success"] = True
            result["response"] = resp.json()[objecttype]
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_endpoint(self, mac_address):
        """
        Get endpoint details.

        :param mac_address: MAC address of the endpoint
        :return: result dictionary
        """
        is_valid = ERS._mac_test(mac_address)

        if not is_valid:
            raise InvalidMacAddress(
                f"{mac_address}. Must be in the form of AA:BB:CC:00:11:22"
            )
        else:
            self.ise.headers.update(
                {"ACCEPT": "application/json", "Content-Type": "application/json"}
            )

            result = {
                "success": False,
                "response": "",
                "error": "",
            }

            resp = self.ise.get(
                f"{self.url_base}/config/endpoint?filter=mac.EQ.{mac_address}",
                timeout=self.timeout,
            )
            found_endpoint = resp.json()

            if found_endpoint["SearchResult"]["total"] == 1:
                result = self.get_object(
                    f"{self.url_base}/config/endpoint/",
                    found_endpoint["SearchResult"]["resources"][0]["id"],
                    "ERSEndPoint",
                )
                return result
            elif found_endpoint["SearchResult"]["total"] == 0:
                result["response"] = f"{mac_address} not found"
                result["error"] = 404
                return result

            else:
                result["response"] = f"{mac_address} not found"
                result["error"] = resp.status_code
                return result

    def add_endpoint(
        self,
        name,
        mac,
        group_id,
        static_profile_assigment="false",
        static_group_assignment="true",
        profile_id="",
        description="",
        portalUser="",
        customAttributes={},
    ):
        """
        Add a user to the local user store.

        :param name: Name
        :param mac: Macaddress
        :param group_id: OID of group to add endpoint in
        :param static_profile_assigment: Set static profile
        :param static_group_assignment: Set static group
        :param profile_id: OID of profile
        :param description: User description
        :param portaluser: Portal username
        :param customAttributes: key value pairs of custom attributes
        :return: result dictionary
        """
        is_valid = ERS._mac_test(mac)
        if not is_valid:
            raise InvalidMacAddress(f"{mac}. Must be in the form of AA:BB:CC:00:11:22")
        else:
            self.ise.headers.update(
                {"ACCEPT": "application/json", "Content-Type": "application/json"}
            )

            result = {
                "success": False,
                "response": "",
                "error": "",
            }

            data = {
                "ERSEndPoint": {
                    "name": name,
                    "description": description,
                    "mac": mac,
                    "profileId": profile_id,
                    "staticProfileAssignment": static_profile_assigment,
                    "groupId": group_id,
                    "staticGroupAssignment": static_group_assignment,
                    "portalUser": portalUser,
                    "customAttributes": {"customAttributes": customAttributes},
                }
            }

            resp = self._request(
                f"{self.url_base}/config/endpoint",
                method="post",
                data=json.dumps(data),
            )
            if resp.status_code == 201:
                result["success"] = True
                result["response"] = f"{name} Added Successfully"
                return result
            else:
                return ERS._pass_ersresponse(result, resp)

    def delete_endpoint(self, mac):
        """
        Delete an endpoint.

        :param mac: Endpoint Macaddress
        :return: Result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        resp = self.ise.get(
            f"{self.url_base}/config/endpoint?filter=mac.EQ.{mac}",
            timeout=self.timeout,
        )
        found_endpoint = resp.json()
        if found_endpoint["SearchResult"]["total"] == 1:
            endpoint_oid = found_endpoint["SearchResult"]["resources"][0]["id"]
            resp = self._request(
                f"{self.url_base}/config/endpoint/{endpoint_oid}",
                method="delete",
            )

            if resp.status_code == 204:
                result["success"] = True
                result["response"] = f"{mac} Deleted Successfully"
                return result
            elif resp.status_code == 404:
                result["response"] = f"{mac} not found"
                result["error"] = resp.status_code
                return result
            else:
                return ERS._pass_ersresponse(result, resp)
        elif found_endpoint["SearchResult"]["total"] == 0:
            result["response"] = f"{mac} not found"
            result["error"] = 404
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_identity_groups(self, filter=None):
        """
        Get all identity groups.

        :param filter: ISE style filter syntax. Default: None
        :return: result dictionary
        """
        return self._get_groups(
            f"{self.url_base}/config/identitygroup",
            filter=filter
        )

    def get_identity_group(self, group):
        """
        Get identity group details.

        :param group: Name of the identity group
        :return: result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        resp = self.ise.get(
            f"{self.url_base}/config/identitygroup?filter=name.EQ.{group}",
            timeout=self.timeout,
        )
        found_group = resp.json()

        if found_group["SearchResult"]["total"] == 1:
            result = self.get_object(
                f"{self.url_base}/config/identitygroup/",
                found_group["SearchResult"]["resources"][0]["id"],
                "IdentityGroup",
            )
            return result
        elif found_group["SearchResult"]["total"] == 0:
            result["response"] = f"{group} not found"
            result["error"] = 404
            return result

        else:
            result["response"] = f"{group} not found"
            result["error"] = resp.status_code
            return result

    def get_users(self):
        """
        Get all internal users.

        :return: List of tuples of user details
        """
        return self._get_objects(
            f"{self.url_base}/config/internaluser"
        )

    def get_user(self, user_id):
        """
        Get user detailed info.

        :param user_id: User ID
        :return: result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        resp = self.ise.get(
            f"{self.url_base}/config/internaluser?filter=name.EQ.{user_id}",
            timeout=self.timeout,
        )
        found_user = resp.json()

        if found_user["SearchResult"]["total"] == 1:
            result = self.get_object(
                f"{self.url_base}/config/internaluser/",
                found_user["SearchResult"]["resources"][0]["id"],
                "InternalUser",
            )
            return result
        elif found_user["SearchResult"]["total"] == 0:
            result["response"] = f"{user_id} not found"
            result["error"] = 404
            return result
        else:
            result["response"] = "Unknown error"
            result["error"] = resp.status_code
            return result

    def get_user_by_email(self, user_email):
        """
        Get user detailed info.

        :param user_email: User Email Address
        :return: result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        resp = self.ise.get(
            f"{self.url_base}/config/internaluser?filter=email.EQ.{user_email}",
            timeout=self.timeout,
        )
        found_user = resp.json()

        if found_user["SearchResult"]["total"] == 1:
            result = self.get_object(
                f"{self.url_base}/config/internaluser/",
                found_user["SearchResult"]["resources"][0]["id"],
                "InternalUser",
            )
            return result
        elif found_user["SearchResult"]["total"] == 0:
            result["response"] = f"{user_email} not found"
            result["error"] = 404
            return result
        else:
            result["response"] = "Unknown error"
            result["error"] = resp.status_code
            return result

    def get_admin_user(self, user_id):
        """
        Get admin user detailed info.

        :param user_id: User ID
        :return: result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        resp = self.ise.get(
            f"{self.url_base}/config/adminuser?filter=name.EQ.{user_id}",
            timeout=self.timeout,
        )
        found_user = resp.json()

        if found_user["SearchResult"]["total"] == 1:
            result = self.get_object(
                f"{self.url_base}/config/adminuser/",
                found_user["SearchResult"]["resources"][0]["id"],
                "AdminUser",
            )
            return result
        elif found_user["SearchResult"]["total"] == 0:
            result["response"] = f"{user_id} not found"
            result["error"] = 404
            return result
        else:
            result["response"] = "Unknown error"
            result["error"] = resp.status_code
            return result

    def add_user(
        self,
        user_id,
        password,
        user_group_oid,
        enable="",
        first_name="",
        last_name="",
        email="",
        description="",
    ):
        """
        Add a user to the local user store.

        :param user_id: User ID
        :param password: User password
        :param user_group_oid: OID of group to add user to
        :param enable: Enable password used for Tacacs
        :param first_name: First name
        :param last_name: Last name
        :param email: email address
        :param description: User description
        :return: result dictionary
        """
        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        data = {
            "InternalUser": {
                "name": user_id,
                "password": password,
                "enablePassword": enable,
                "firstName": first_name,
                "lastName": last_name,
                "email": email,
                "description": description,
                "identityGroups": user_group_oid,
            }
        }

        resp = self._request(
            f"{self.url_base}/config/internaluser",
            method="post",
            data=json.dumps(data),
        )
        if resp.status_code == 201:
            result["success"] = True
            result["response"] = f"{user_id} Added Successfully"
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def delete_user(self, user_id):
        """
        Delete a user.

        :param user_id: User ID
        :return: Result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        resp = self.ise.get(
            f"{self.url_base}/config/internaluser?filter=name.EQ.{user_id}",
            timeout=self.timeout,
        )
        found_user = resp.json()

        if found_user["SearchResult"]["total"] == 1:
            user_oid = found_user["SearchResult"]["resources"][0]["id"]
            resp = self._request(
                f"{self.url_base}/config/internaluser/{user_oid}",
                method="delete",
            )

            if resp.status_code == 204:
                result["success"] = True
                result["response"] = f"{user_id} Deleted Successfully"
                return result
            elif resp.status_code == 404:
                result["response"] = f"{user_id} not found"
                result["error"] = resp.status_code
                return result
            else:
                return ERS._pass_ersresponse(result, resp)
        elif found_user["SearchResult"]["total"] == 0:
            result["response"] = f"{user_id} not found"
            result["error"] = 404
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_device_groups(self):
        """
        Get a list tuples of device groups.
        
        :return:
        """
        return self._get_groups(
            f"{self.url_base}/config/networkdevicegroup"
        )

    def get_device_group(self, device_group_oid=None, name=None):
        """
        Get a device group(s) details by group id or name.

        device_group_oid takes priority for searching over name

        :param device_group_oid: oid of the device group (default None)
        :param name: name of group (default None)
        :return: result dictionary or list of dictionaries
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        if device_group_oid is not None:
            device_group = self.get_object(
                f"{self.url_base}/config/networkdevicegroup/",
                device_group_oid,
                "NetworkDeviceGroup",
            )  # noqa E501
        elif name is not None:
            # Using quote() function from urllib.parse to urlencode the name of the group
            resp = self.ise.get(
                f"{self.url_base}/config/networkdevicegroup?filter=name.contains.{quote(name)}",
                timeout=self.timeout,
            )
            found_group = resp.json()

            if found_group["SearchResult"]["total"] == 1:
                group_oid = found_group["SearchResult"]["resources"][0]["id"]
                device_group = self.get_device_group(device_group_oid=group_oid)
            elif found_group["SearchResult"]["total"] == 0:
                return {"success": False, "response": "", "error": 404}
            else:
                device_group = [
                    self.get_device_group(device_group_oid=group["id"])
                    for group in found_group["SearchResult"]["resources"]
                ]

        return device_group

    def add_device_group(self, name, description=""):
        """
        Add a Network Device Group

        :param name: Full name of the group to add. (Example: "Device Type#All Device Types#ASA Firewall)
        :param description: Optional description for group

        :return: Result dictionary
        """
        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        data = {
            "NetworkDeviceGroup": {
                "name": name,
                "description": description,
                "othername": name.split("#")[0],
            }
        }

        resp = self._request(
            f"{self.url_base}/config/networkdevicegroup",
            method="post",
            data=json.dumps(data),
        )

        if resp.status_code == 201:
            result["success"] = True
            result["response"] = f"{name} Added Successfully"
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def update_device_group(self, device_group_oid, name=None, description=None):
        """
        Update a Network Device Group with provided settings.

        :param device_group_oid: Unique ID for group
        :param name: New name for group (default None)
        :param description: New description for group (default None)

        :return: results dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        resp = self.get_device_group(device_group_oid=device_group_oid)

        if not resp["success"]:
            # Pass through the 404 error from the lookup
            return resp

        device_group = resp["response"]

        # Set initial values to current values
        data = {
            "NetworkDeviceGroup": {
                "name": device_group["name"],
                "description": device_group["description"],
                "othername": device_group["othername"],
            }
        }

        if name:
            data["NetworkDeviceGroup"]["name"] = name
        if description:
            data["NetworkDeviceGroup"]["description"] = description

        resp = self._request(
            f"{self.url_base}/config/networkdevicegroup/{device_group_oid}",
            method="put",
            data=json.dumps(data),
        )

        if resp.status_code == 200:
            result["success"] = True
            result["response"] = f"{device_group_oid} Updated Successfully"
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def delete_device_group(self, name):
        """
        Delete a Network Device Group

        :param name: Full name of the group to delete. (Example: "Device Type#All Device Types#ASA Firewall)

        :return: Result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        # Using quote() function from urllib.parse to urlencode the name of the group
        resp = self.ise.get(
            f"{self.url_base}/config/networkdevicegroup?filter=name.contains.{quote(name)}",
            timeout=self.timeout,
        )
        found_group = resp.json()
        if found_group["SearchResult"]["total"] == 1:
            group_oid = found_group["SearchResult"]["resources"][0]["id"]
            resp = self._request(
                f"{self.url_base}/config/networkdevicegroup/{group_oid}",
                method="delete",
            )

            if resp.status_code == 204:
                result["success"] = True
                result["response"] = f"{name} Deleted Successfully"
                return result
            elif resp.status_code == 404:
                result["response"] = f"{name} not found"
                result["error"] = resp.status_code
                return result
            else:
                return ERS._pass_ersresponse(result, resp)
        elif found_group["SearchResult"]["total"] == 0:
            result["response"] = f"{name} not found"
            result["error"] = 404
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_devices(self, filter=None):
        """
        Get a list of devices.

        :return: result dictionary
        """
        return self._get_objects(
            f"{self.url_base}/config/networkdevice",
            filter=filter
        )

    def get_device(self, device):
        """
        Get a device detailed info.

        :param device: device_name
        :return: result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        resp = self.ise.get(
            f"{self.url_base}/config/networkdevice?filter=name.EQ.{device}",
            timeout=self.timeout,
        )
        found_device = resp.json()

        if found_device["SearchResult"]["total"] == 1:
            result = self.get_object(
                f"{self.url_base}/config/networkdevice/",
                found_device["SearchResult"]["resources"][0]["id"],
                "NetworkDevice",
            )
            return result
        elif found_device["SearchResult"]["total"] == 0:
            result["response"] = f"{device} not found"
            result["error"] = 404
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def add_device(
        self,
        name=None,
        ip_address=None,
        mask=32,
        description="",
        dev_group=None,
        dev_location="Location#All Locations",
        dev_type="Device Type#All Device Types",
        dev_ipsec="IPSEC#Is IPSEC Device#No",
        radius_key=None,
        snmp_ro=None,
        dev_profile="Cisco",
        tacacs_shared_secret=None,
        tacacs_connect_mode_options="ON_LEGACY",
        coa_port=1700,
        snmp_version="TWO_C",
        snmp_polling_interval=3600,
        snmp_link_trap_query="true",
        snmp_mac_trap_query="true",
        snmp_originating_policy_services_node="Auto",
        device_payload=None,
    ):
        """
        Add a device.

        :param name: name of device
        :param ip_address: IP address of device
        :param description: Device description (default "")
        :param dev_group: Custom device group name, string or list (default None)
        :param dev_location: Device location (default "Location#All Locations")
        :param dev_type: Device type (default "Device Type#All Device Types")
        :param dev_ipsec: IPSEC Status for device (default "IPSEC#Is IPSEC Device#No")
        :param radius_key: Radius shared secret (default None)
        :param snmp_ro: SNMP read only community string (default None)
        :param dev_profile: Device profile (default "Cisco")
        :param tacacs_shared_secret: Tacacs shared secret  (default None)
        :param tacacs_connect_mode_options: Tacacs connect mode  (default 'ON_LEGACY',)
        :param coa_port: Change of Auth port  (default 1700)
        :param snmp_version: SNMP Version  (default "TWO_C")
        :param snmp_polling_interval: SNMP Polling Interval  (default 3600)
        :param snmp_link_trap_query: SNMP Link Trap  (default "true")
        :param snmp_mac_trap_query: SNMP MAC Trap  (default "true")
        :param snmp_originating_policy_services_node: SNMP Policy Node  (default "Auto")
        :param device_payload: A single dictionary representing desired device configuration. If provided it overrides individual settings (default None) # noqa E501

        :return: Result dictionary
        """
        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        # If a payload was provided, use it as is
        if device_payload:
            data = {"NetworkDevice": device_payload}

            # Pull name out of payload to use in response
            name = device_payload["name"]

        # If no payload provided, build from provided details
        elif name and ip_address:
            data = {
                "NetworkDevice": {
                    "name": name,
                    "description": description,
                    "profileName": dev_profile,
                    "coaPort": coa_port,
                    "NetworkDeviceIPList": [],
                    "NetworkDeviceGroupList": [dev_type, dev_location, dev_ipsec],
                }
            }

            if type(ip_address) is str:
                data["NetworkDevice"]["NetworkDeviceIPList"].append(
                    {
                        "ipaddress": ip_address,
                        "mask": mask,
                    }
                )

            elif type(ip_address) is list:
                for ips in ip_address:
                    data["NetworkDevice"]["NetworkDeviceIPList"].append(
                        {
                            "ipaddress": ips,
                            "mask": mask,
                        }
                    )

            if tacacs_shared_secret is not None:
                data["NetworkDevice"]["tacacsSettings"] = {
                    "sharedSecret": tacacs_shared_secret,
                    "connectModeOptions": tacacs_connect_mode_options,
                }

            if radius_key is not None:
                data["NetworkDevice"]["authenticationSettings"] = {
                    "networkProtocol": "RADIUS",
                    "radiusSharedSecret": radius_key,
                    "enableKeyWrap": "false",
                }

            if snmp_ro is not None:
                data["NetworkDevice"]["snmpsettings"] = {
                    "version": snmp_version,
                    "roCommunity": snmp_ro,
                    "pollingInterval": snmp_polling_interval,
                    "linkTrapQuery": snmp_link_trap_query,
                    "macTrapQuery": snmp_mac_trap_query,
                    "originatingPolicyServicesNode": snmp_originating_policy_services_node,
                }

            if dev_group is not None:
                if isinstance(dev_group, str):
                    data["NetworkDevice"]["NetworkDeviceGroupList"].append(dev_group)
                elif isinstance(dev_group, list):
                    data["NetworkDevice"]["NetworkDeviceGroupList"] += dev_group

        # If neither a payload or name/ip_address provided exit with error
        else:
            result["success"] = False
            result[
                "error"
            ] = "You must provide either (name, ip_address) or (device_payload) values to create a device"
            return result

        resp = self._request(
            f"{self.url_base}/config/networkdevice",
            method="post",
            data=json.dumps(data),
        )

        if resp.status_code == 201:
            result["success"] = True
            result["response"] = f"{name} Added Successfully"
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def delete_device(self, device):
        """
        Delete a device.

        :param device: device_name
        :return: Result dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        resp = self.ise.get(
            f"{self.url_base}/config/networkdevice?filter=name.EQ.{device}",
            timeout=self.timeout,
        )
        found_device = resp.json()
        if found_device["SearchResult"]["total"] == 1:
            device_oid = found_device["SearchResult"]["resources"][0]["id"]
            resp = self._request(
                f"{self.url_base}/config/networkdevice/{device_oid}",
                method="delete",
            )

            if resp.status_code == 204:
                result["success"] = True
                result["response"] = f"{device} Deleted Successfully"
                return result
            elif resp.status_code == 404:
                result["response"] = f"{device} not found"
                result["error"] = resp.status_code
                return result
            else:
                return ERS._pass_ersresponse(result, resp)
        elif found_device["SearchResult"]["total"] == 0:
            result["response"] = f"{device} not found"
            result["error"] = 404
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def update_device(  # noqa C901
        self,
        name,
        new_name=None,
        ip_address=None,
        mask=None,
        description=None,
        dev_group=None,
        dev_location=None,
        dev_type=None,
        dev_ipsec=None,
        radius_key=None,
        snmp_ro=None,
        dev_profile=None,
        tacacs_shared_secret=None,
        tacacs_connect_mode_options=None,
        coa_port=None,
        snmp_version=None,
        snmp_polling_interval=None,
        snmp_link_trap_query=None,
        snmp_mac_trap_query=None,
        snmp_originating_policy_services_node=None,
        disable_tacacs=False,
        disable_radius=False,
        disable_snmp=False,
        device_payload=None,
    ):
        """
        Update a Network Device with provided settings.

        New settings not provided will remain at current setting

        :param name: Current name of the device
        :param new_name: New name for device (default None)
        :param ip_address: New ip address for device (default None)
        :param mask: New network mask for device (default None)
        :param description: New description for device (default None)
        :param dev_group: New custom group(s) for device - string or list (default None)
        :param dev_location: New location for device (default None)
        :param dev_type: New device type for device (default None)
        :param dev_ipsec: New IPSEC status for device (default None)
        :param radius_key: New radius key for device (default None)
        :param snmp_ro: New snmp_ro string for device (default None)
        :param dev_profile: New Device profile for device (default None)
        :param tacacs_shared_secret: New tacacs shared secret for device (default None)
        :param tacas_connect_mode_options: New tacacs mode for device (default None)
        :param coa_port: New COA port for device (default None)
        :param snmp_version: New SNMP Version for device (default None)
        :param snmp_polling_interval: New SNMP polling interval for device (default None)
        :param snmp_link_trap_query: New SNMP link trap query for device (default None)
        :param snmp_mac_trap_query: New SNMP mac trap query for device (default None)
        :param snmp_originating_policy_services_node: New SNMP policy service node for device (default None)
        :param disable_tacacs: Disable TACACS if configured (default False)
        :param disable_radius: Disable Radius if configured (default False) *NOTE: Flag placed for completeness, but ERS API currently doesn't support disabling RADIUS*  # noqa E501
        :param disable_snmp: Disable SNMP if configured (default False)
        :param device_payload: A single dictionary representing desired device configuration. If provided it overrides individual settings (default None)  # noqa E501

        :return: results dictionary
        """
        self.ise.headers.update(
            {"ACCEPT": "application/json", "Content-Type": "application/json"}
        )

        result = {
            "success": False,
            "response": "",
            "error": "",
        }

        resp = self.get_device(device=name)

        if not resp["success"]:
            # Pass through the 404 error from the lookup
            return resp

        device = resp["response"]

        # Find Device ID for use in update request
        device_oid = device.pop("id")

        # If a full device payload provided, use it for the update request
        if device_payload:
            device = device_payload

        # If no specific payload provided, update individual values provided
        else:
            # Update basic device properties
            if new_name:
                device["name"] = new_name
            if description:
                device["description"] = description
            if dev_profile:
                device["profileName"] = dev_profile
            if coa_port:
                device["coaPort"] = coa_port

            # Update device ip address
            # TODO: Currently only supports a device with a single IP address
            if ip_address:
                device["NetworkDeviceIPList"][0]["ipaddress"] = ip_address
            if mask:
                device["NetworkDeviceIPList"][0]["mask"] = mask

            # Update radius settings
            if disable_radius:
                # device.pop("authenticationSettings", None)
                # BUG in ERS API: Doesn't seem to be a way to successfully disable RADIUS from the API
                # Some details in this post
                # https://community.cisco.com/t5/network-access-control/ise-ers-network-device-api-put-update-operation-how-to-remove/td-p/4028001
                result[
                    "error"
                ] = "Error: ERS API doesn't support disabling RADIUS. You'll need to delete/add the device"
                result["success"] = False
                return result
            elif radius_key:
                device["authenticationSettings"] = {
                    "networkProtocol": "RADIUS",
                    "radiusSharedSecret": radius_key,
                    "enableKeyWrap": "false",
                }

            # Update tacacs settings
            if disable_tacacs:
                device.pop("tacacsSettings", None)
            elif tacacs_shared_secret or tacacs_connect_mode_options:
                # Get current tacacs currently configured on device. If not configured build data model
                tacacs_settings = device.pop(
                    "tacacsSettings", {"sharedSecret": None, "connectModeOptions": None}
                )

                # Update new values provided by functions
                if tacacs_shared_secret:
                    tacacs_settings["sharedSecret"] = tacacs_shared_secret
                if tacacs_connect_mode_options:
                    tacacs_settings["connectModeOptions"] = tacacs_connect_mode_options

                # Set a default for connect mode setting if one isn't provided or already configured
                if tacacs_settings["connectModeOptions"] is None:
                    tacacs_settings["connectModeOptions"] = "ON_LEGACY"

                # Update the device with new tacacs settings as long as all factors confgured
                #   This could happen in an odd case where a connect mode change provided without a
                #   TACACS secret and TACACS wasn't already configured. Behavior is to then IGNORE
                #   tacacs completely
                if None not in tacacs_settings.values():
                    device["tacacsSettings"] = tacacs_settings

            # Update snmp settings
            if disable_snmp:
                device.pop("snmpsettings", None)
            elif (
                snmp_ro
                or snmp_version
                or snmp_polling_interval
                or snmp_link_trap_query
                or snmp_mac_trap_query
                or snmp_originating_policy_services_node
            ):
                # Get current SNMP settings from device, or build data model
                snmp_settings = device.pop(
                    "snmpsettings",
                    {
                        "version": None,
                        "roCommunity": None,
                        "pollingInterval": None,
                        "linkTrapQuery": None,
                        "macTrapQuery": None,
                        "originatingPolicyServicesNode": None,
                    },
                )

                # Update new values provided
                if snmp_ro:
                    snmp_settings["roCommunity"] = snmp_ro

                if snmp_version:
                    snmp_settings["version"] = snmp_version

                if snmp_polling_interval:
                    snmp_settings["pollingInterval"] = snmp_polling_interval

                if snmp_link_trap_query:
                    snmp_settings["linkTrapQuery"] = snmp_link_trap_query

                if snmp_mac_trap_query:
                    snmp_settings["macTrapQuery"] = snmp_mac_trap_query

                if snmp_originating_policy_services_node:
                    snmp_settings[
                        "originatingPolicyServicesNode"
                    ] = snmp_originating_policy_services_node

                # Update defaults for common setting should SNMP be newly configured and all settings not provided
                if snmp_settings["version"] is None:
                    snmp_settings["version"] = "TWO_C"

                if snmp_settings["pollingInterval"] is None:
                    snmp_settings["pollingInterval"] = 3600

                if snmp_settings["linkTrapQuery"] is None:
                    snmp_settings["linkTrapQuery"] = "true"

                if snmp_settings["macTrapQuery"] is None:
                    snmp_settings["macTrapQuery"] = "true"

                if snmp_settings["originatingPolicyServicesNode"] is None:
                    snmp_settings["originatingPolicyServicesNode"] = "Auto"

                # Update the device with new snmp settings as long as all factors confgured
                #   This could happen in an odd case where an snmp attribute change provided without a
                #   SNMP RO and SNMP wasn't already configured. Behavior is to then IGNORE
                #   snmp completely
                if None not in snmp_settings.values():
                    device["snmpsettings"] = snmp_settings

            # Update groups
            if dev_group or dev_location or dev_type or dev_ipsec:
                # Groups are a mandatory attribute, let's see what the current configuration is
                groups = device.pop("NetworkDeviceGroupList", None)

                # Determine the current values of the mandatory ISE Groups
                group_location = [
                    group
                    for group in groups
                    if group.startswith("Location#All Locations")
                ][0]
                group_type = [
                    group
                    for group in groups
                    if group.startswith("Device Type#All Device Types")
                ][0]
                group_ipsec = [
                    group
                    for group in groups
                    if group.startswith("IPSEC#Is IPSEC Device")
                ][0]

                # Create a list of any custom groups by removing the mandatory groups from the list
                custom_groups = groups
                custom_groups.pop(groups.index(group_location))
                custom_groups.pop(groups.index(group_type))
                custom_groups.pop(groups.index(group_ipsec))

                # Update the groups to new values if provided
                if dev_location:
                    group_location = dev_location
                if dev_type:
                    group_type = dev_type
                if dev_ipsec:
                    group_ipsec = dev_ipsec
                if dev_group:
                    if isinstance(dev_group, str):
                        custom_groups = [dev_group]
                    elif isinstance(dev_group, list):
                        custom_groups = dev_group

                device["NetworkDeviceGroupList"] = [
                    group_location,
                    group_type,
                    group_ipsec,
                ]
                device["NetworkDeviceGroupList"] += custom_groups

        # Remove possible payload values that aren't used in PUT updates
        device.pop("id", None)
        device.pop("link", None)

        # data for request
        data = {"NetworkDevice": device}

        resp = self._request(
            f"{self.url_base}/config/networkdevice/{device_oid}",
            method="put",
            data=json.dumps(data),
        )

        if resp.status_code == 200:
            result["success"] = True
            # result['response'] = f'{device_group_oid} Updated Successfully'
            result["response"] = resp.json()["UpdatedFieldsList"]
            return result
        else:
            return ERS._pass_ersresponse(result, resp)
