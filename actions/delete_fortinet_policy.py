import json

from lib.san_action import SanFortinetBaseAction


class DeleteAddressGroup(SanFortinetBaseAction):
    def run(self, threat_ip=None):
        status = self.san_device.remove_threat(threat_ip)

        if status is not None:
            result = json.loads(status)
            data = result['result'][0]
            if data['status']['code'] == 0:
                return True, status
        return False, status
