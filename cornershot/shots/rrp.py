from impacket.dcerpc.v5 import rrp

from . import *

TS = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
IFACE_UUID = rrp.MSRPC_UUID_RRP


class RRPShot(BaseRPCShot):

    def __init__(self, username, password, domain, destination, target, dest_port=None, target_port=None):
        BaseRPCShot.__init__(self, username, password, domain, TS, IFACE_UUID, destination, target, dest_port,
                             target_port,
                             state_exception_open=['rpc_s_access_denied', 'ERROR_BAD_NET_NAME'],
                             state_exception_closed=['ERROR_BAD_NETPATH'])

    @staticmethod
    def target_port_range():
        return [445]

    @staticmethod
    def destination_port_range():
        return [445]

    def do_binding(self):
        return r'ncacn_np:%s[\PIPE\winreg]' % self.destination

    def do_rpc_logic(self):
        try:
            resp = rrp.hOpenCurrentUser(self.dce)
        except Exception:
            return

        rrp.hBaseRegSaveKey(self.dce, resp['phKey'], f'\\\\{self.target}\\shmores\\file')
