from st2common.runners.base_action import Action

from fortinet_policy import FortinetApi


class SanFortinetBaseAction(Action):
    def __init__(self, config):
        super(SanFortinetBaseAction, self).__init__(config)
        self._firewall_ip = self.config['firewall_ip']
        self._username = self.config['username']
        self._password = self.config['password']
        self.san_device = self.device()

    def device(self):
        device = FortinetApi(fortinet=self._firewall_ip, username=self._username,
                             password=self._password)

        return device
