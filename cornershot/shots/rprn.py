from impacket.dcerpc.v5 import rprn
from impacket.dcerpc.v5.dtypes import NULL

from . import *

TS = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
IFACE_UUID = rprn.MSRPC_UUID_RPRN


class RPRNShot(BaseRPCShot):

    def __init__(self, username, password, domain, destination, target, dest_port=None, target_port=None):
        BaseRPCShot.__init__(self, username, password, domain, TS, IFACE_UUID, destination, target, dest_port,
                             target_port,state_exception_closed=['INVALID_PRINTER_NAME'])

    @staticmethod
    def target_port_range():
        yield from range(1, 445)
        yield from range(446, 65535 + 1)

    @staticmethod
    def destination_port_range():
        return [445]

    def do_binding(self):
        return r'ncacn_np:%s[\PIPE\spoolss]' % self.destination

    def _create_request(self):
        request = rprn.RpcOpenPrinter()
        str = f"http://{self.target}:{self.trgt_port}/printers/ppp/.printer"

        request['pPrinterName'] = '%s\x00' % str
        request['pDatatype'] = NULL
        request['pDevModeContainer']['pDevMode'] = NULL
        request['AccessRequired'] = rprn.SERVER_READ

        return request

    def do_rpc_logic(self):
        request = self._create_request()
        self.dce.request(request)
