from impacket.dcerpc.v5 import even
from impacket.dcerpc.v5.dtypes import NULL

from . import *

TS = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')
IFACE_UUID = even.MSRPC_UUID_EVEN
FILTERED_PORT_TIMEOUT = 20


class EVENShot(BaseRPCShot):

    def __init__(self, username, password, domain, destination, target, dest_port=None, target_port=None):
        BaseRPCShot.__init__(self, username, password, domain, TS, IFACE_UUID, destination, target, dest_port,
                             target_port,
                             state_exception_open=['BAD_NETWORK_NAME', 'NAME_NOT_FOUND', 'ACCESS_DENIED'],
                             state_exception_closed=['BAD_NETWORK_PATH'])

    @staticmethod
    def target_port_range():
        return [445]

    @staticmethod
    def destination_port_range():
        return [445]

    def do_binding(self):
        return r'ncacn_np:%s[\PIPE\eventlog]' % self.destination

    def _create_request(self):
        request = even.ElfrOpenBELW()

        str = f"\\??\\UNC\\{self.target}\\share\\file"

        if self.trgt_port != 445:
            # Will only work if WebDav service is working on client OS
            str = f"\\??\\UNC\\{self.target}@{self.trgt_port}\\DavWWWRoot\\share\\file\x00"

        request['UNCServerName'] = NULL
        request['BackupFileName'] = str
        request['MajorVersion'] = 1
        request['MinorVersion'] = 1

        return request

    def do_rpc_logic(self):
        request = self._create_request()
        self.dce.request(request)
