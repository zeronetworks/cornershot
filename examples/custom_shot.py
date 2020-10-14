from cornershot.cornershot import CornerShot
from cornershot.shots import BaseRPCShot
from impacket.dcerpc.v5 import even6, epm
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

TS = ('<RPC UUID>', '<Version>')
IFACE_UUID = even6.MSRPC_UUID_EVEN6


class MyCustomShot(BaseRPCShot):

    def __init__(self, username, password, domain, destination, target, dest_port=None, target_port=None):
        BaseRPCShot.__init__(self, username, password, domain, TS, IFACE_UUID, destination, target, dest_port,target_port)

    @staticmethod
    def target_port_range():
        # Port ranges that need to be accessible over the destination host, in order for the shot to succeed
        return [445]

    @staticmethod
    def destination_port_range():
        # Port ranges that can be scanned over the target host
        return [445]

    def do_binding(self):
        # Return the required binding string
        pass

    def do_rpc_logic(self):
        # Create, send and receive RPC packets
        pass


if __name__ == '__main__':
    # Credentials of an authenticated user in the domain
    username = 'username'
    passwrod = 'password'
    domain = 'domain.org'

    cs = CornerShot(username, passwrod, domain, shots=[MyCustomShot])
    cs.add_shots('192.168.1.1,192.168.1.1', '192.168.2.0/24,192.168.5.5')
    results = cs.open_fire()
    print(results)
