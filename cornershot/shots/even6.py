from impacket.dcerpc.v5 import even6, epm
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

from . import *

TS = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
IFACE_UUID = even6.MSRPC_UUID_EVEN6


class EVEN6Shot(BaseRPCShot):

    def __init__(self, username, password, domain, destination, target, dest_port=None, target_port=None):
        BaseRPCShot.__init__(self, username, password, domain, TS, IFACE_UUID, destination, target, dest_port,
                             target_port, auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                             state_exception_closed=["BAD_NETPATH"], state_exception_open=['ERROR_FILE_NOT_FOUND'])

    @staticmethod
    def target_port_range():
        return [445]

    @staticmethod
    def destination_port_range():
        return [135]

    def do_binding(self):
        return epm.hept_map(self.destination, even6.MSRPC_UUID_EVEN6, protocol='ncacn_ip_tcp')

    def _create_request(self):
        request = even6.EvtRpcOpenLogHandle()

        request['Channel'] = f'\\\\{self.target}\\share\\file\x00'
        request['Flags'] = 2  # specifies a file name

        return request

    def do_rpc_logic(self):
        request = self._create_request()
        self.dce.request(request)
