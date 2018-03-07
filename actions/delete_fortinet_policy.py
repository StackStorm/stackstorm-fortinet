import json

from lib.action import FortinetBaseAction


class DeleteAddressGroup(FortinetBaseAction):
    def run(self, threat_ip=None):
        status = self.device.remove_threat(threat_ip, True)

        if status is not None:
            result = json.loads(status)
            data = result['result'][0]
            if data['status']['code'] == 0:
                return True, status
        return False, status
