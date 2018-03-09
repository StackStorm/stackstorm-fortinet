import json
import random
import requests
import urllib3


class FortinetApi(object):
    def __init__(self, fortinet, username, password):
        self.fortinet = fortinet
        self.username = username
        self.password = password
        self.session = None

    def get_session_id(self):
        if self.session is None:
            id = self.get_random_id()
            data = {"params": [{"url": "sys/login/user",
                                "data": [{"user": self.username,
                                          "passwd": self.password}]}],
                    "session": 1, "id": id, "method": "exec"}
            content = self.post(data)
            if content is not None and 'session' in content:
                response = json.loads(content)
                self.session = response['session']
        return self.session

    def get_managed_devices(self):
        devices = None
        session = self.get_session_id()
        id = self.get_random_id()
        data = {"params": [{"url": "dvmdb/device"}],
                "session": session, "id": id, "method": "get"}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            devices = data['data']
        return devices

    def get_addresses(self):
        addresses = None
        session = self.get_session_id()
        id = self.get_random_id()
        data = \
            {"params": [{"url": "pm/config/adom/root/obj/firewall/address"}],
                "session": session, "id": id, "method": "get"}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            addresses = data['data']
        return addresses

    def add_address(self, ipAddress):
        session = self.get_session_id()
        id = self.get_random_id()
        data = {"params": [{"url": "pm/config/adom/root/obj/firewall/address",
                            "data": [{"color": 13, "name": ipAddress,
                                      "type": 0, "associated-interface": "any",
                                      "subnet": [ipAddress, "255.255.255.255"]
                                      }]}], "session": session, "id": id,
                "method": "add"}
        return self.post(data)

    def delete_address(self, ipAddress):
        session = self.get_session_id()
        id = self.get_random_id()
        url = 'pm/config/adom/root/obj/firewall/address/{0}'.format(ipAddress)
        data = {"params": [{"url": url}], "session": session,
                "id": id, "method": "delete"}
        return self.post(data)

    def get_address_groups(self):
        groups = None
        session = self.get_session_id()
        id = self.get_random_id()
        data = {"params": [{"url": "pm/config/adom/root/obj/firewall/addrgrp"}],
                "session": session, "id": id, "method": "get"}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            groups = data['data']
        return groups

    def add_address_group(self, group, members):
        session = self.get_session_id()
        id = self.get_random_id()
        data = {"params": [{"url": "pm/config/adom/root/obj/firewall/addrgrp",
                            "data": [{"color": 13, "visbility": "enable", "comment": "",
                                      "name": group, "member": members}]}],
                "session": session, "id": id, "method": "add"}
        return self.post(data)

    def update_group(self, group, members):
        session = self.get_session_id()
        id = self.get_random_id()
        data = {"params": [{"url": "pm/config/adom/root/obj/firewall/addrgrp",
                            "data": [{"color": 13, "visbility": "enable", "comment": "",
                                      "name": group, "member": members}]}], "session": session,
                "id": id, "method": "update"}
        return self.post(data)

    def get_policy_packages(self):
        packages = None
        session = self.get_session_id()
        id = self.get_random_id()
        url = 'pm/pkg/adom/root'
        data = {"params": [{"url": url}], "session": session, "id": id, "method": "get"}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            packages = data['data']
        return packages

    def get_policies(self, package):
        policies = None
        session = self.get_session_id()
        id = self.get_random_id()
        url = 'pm/config/adom/root/pkg/{0}/firewall/policy'.format(package)
        data = {"params": [{"url": url}], "session": session, "id": id, "method": "get"}
        content = self.post(data)
        if content is not None and 'data' in content:
            j = json.loads(content)
            result = j['result']
            data = result[0]
            policies = data['data']
        return policies

    def add_deny_sip_policy(self, package, name, srcAddressGroup, srcInterface=['any'],
                            dstAddressGroup=['all'], dstInterface=['any'],
                            comments='json web service rule'):
        return self.add_deny_policy(package, name, [srcAddressGroup], srcInterface,
                                    dstAddressGroup, dstInterface, comments)

    def add_deny_dip_policy(self, package, name, dstAddressGroup, dstInterface=['any'],
                            srcAddressGroup=['all'], srcInterface=['any'],
                            comments='json web service rule'):
        return self.add_deny_policy(package, name, srcAddressGroup, srcInterface,
                                    [dstAddressGroup], dstInterface, comments)

    def add_deny_policy(self, package, name, srcAddressGroup, srcInterface, dstAddressGroup,
                        dstInterface, comments):
        session = self.get_session_id()
        id = self.get_random_id()
        url = 'pm/config/adom/root/pkg/{0}/firewall/policy'.format(package)
        data = {"params": [{"url": url,
                            "data": [{"action": "deny", "comments": comments,
                                      "dstaddr": dstAddressGroup,
                                      "dstintf": dstInterface,
                                      "global-label": name,
                                      "ippool": "enable",
                                      "logtraffic": "disable",
                                      "nat": "disable",
                                      "schedule": ["always"],
                                      "service": ["ALL"],
                                      "srcaddr": srcAddressGroup,
                                      "srcintf": srcInterface,
                                      "status": "enable"}]}],
                "session": session, "id": id, "method": "add"}
        return self.post(data)

    def logout(self):
        status = None
        if self.session is not None:
            id = self.get_random_id()
            data = {"verbose": 1, "params": [{"url": "sys/logout"}], "session": self.session,
                    "id": id, "method": "exec"}
            status = self.post(data)
        return status

    def get_random_id(self):
        return random.randint(1, 0xFFFF)

    def post(self, data):
        content = None
        url = 'https://{0}/jsonrpc'.format(self.fortinet)
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        r = requests.post(url, verify=False, headers=headers, json=data)
        code = r.status_code
        if code == 200:
            content = r.content
        else:
            print '{0} -> {1}'.format(str(code), r.content)
        return content

    def add_threat(self, threat, group='Block IPs'):
        status = None
        session = self.get_session_id()
        if session is not None:
            add = True
            addresses = self.get_addresses()
            if addresses is not None:
                for address in addresses:
                    name = address['name']
                    if name == threat:
                        add = False
                        break
            if add:
                print 'Creating address object for: {0}'.format(threat)
                self.add_address(threat)

            members = None
            groups = self.get_address_groups()
            if groups is not None:
                for g in groups:
                    name = g['name']
                    if name == group:
                        members = g['member']

            if members is None:
                placeholder = '127.0.0.1'
                self.add_address(placeholder)
                members = [placeholder, threat]
                status = self.add_address_group(group, members)
            else:
                name = type(members).__name__
                if name == 'unicode' or name == 'str':
                    members = [members]
                if threat not in members:
                    print 'Adding address object: {0} to group: {1}'.format(threat, group)
                    members.append(threat)
                    status = self.update_group(group, members)

            packages = self.get_policy_packages()
            if packages is not None:
                for package in packages:
                    name = package['name']
                    if name is not None:
                        sip = True
                        dip = True
                        policies = self.get_policies(name)
                        if policies is not None:
                            for policy in policies:
                                label = policy['global-label']
                                if label == 'DENY SIP':
                                    sip = False
                                elif label == 'DENY DIP':
                                    dip = False
                            if sip:
                                print 'Creating DENY SIP policy rule for: {0}'.format(name)
                                self.add_deny_sip_policy(name, 'DENY SIP', group)
                            if dip:
                                print 'Creating DENY DIP policy rule for: {0}'.format(name)
                                self.add_deny_dip_policy(name, 'DENY DIP', group)
        else:
            print 'Unable to authenticate user and generate session ID'
        return status

    def remove_threat(self, threat, group='Block IPs'):
        status = None
        session = self.get_session_id()
        if session is not None:
            members = None
            groups = self.get_address_groups()
            if groups is not None:
                for g in groups:
                    name = g['name']
                    if name == group:
                        members = g['member']
            if members is not None:
                name = type(members).__name__
                if name == 'unicode' or name == 'str':
                    if members == threat:
                        placeholder = '127.0.0.1'
                        add = True
                        addresses = self.get_addresses()
                        if addresses is not None:
                            for address in addresses:
                                name = address['name']
                                if name == placeholder:
                                    add = False
                                    break
                        if add:
                            print 'Creating address object for: {0}'.format(placeholder)
                            self.add_address(placeholder)

                        print 'Removing threat: {0} from group: {1}, adding: {2} to prevent an ' \
                              'error'.format(threat, group, placeholder)
                        status = self.update_group(group, [placeholder])
                        self.delete_address(threat)
                else:
                    print 'Removing threat: {0} from group: {1}'.format(threat, group)
                    if threat in members:
                        members.remove(threat)
                        status = self.update_group(group, members)
                        self.delete_address(threat)
        return status


urllib3.disable_warnings()

if __name__ == "__main__":
    fortimanager = '10.65.47.23'
    username = 'admin'
    password = ''
    threat = '192.168.10.5'
    api = FortinetApi(fortimanager, username, password)
    status = api.add_threat(threat)
    print status
    status = api.remove_threat(threat)
    print status
    api.logout()
