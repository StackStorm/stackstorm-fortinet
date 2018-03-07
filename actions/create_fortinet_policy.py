import json

from lib.action import FortinetBaseAction


class CreateAddressGroup(FortinetBaseAction):
    def run(self, threat_ip=None):
        status = self.san_device.add_threat(threat_ip)
        
        if status != None:
            result = json.loads(status)
            data = result['result'][0]
            if data['status']['code'] == 0:
                return (True, status)
        return (False, status)
