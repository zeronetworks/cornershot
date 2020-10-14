import time
from abc import ABCMeta, abstractmethod

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import DCERPCException

from .. import logger

MIN_PORT = 1
MAX_PORT = 65535

SMB_PORT = 445
RPC_EPMP_PORT = 135
PS_HTTP_WSMAN = 5985
PS_HTTPS_WSMAN = 5986

DEFAULT_DEST_PORT = SMB_PORT
DEFAULT_TRGT_PORT = SMB_PORT

DEFAULT_HOST = "127.0.0.1"

PORT_OPEN = 'open'
PORT_UNKNOWN = 'unknown'
PORT_FILTERED = 'filtered'
PORT_CLOSED = 'close'

UPPER_TIME_THRESHOLD = 50
FILTERED_TIME_THRESHOLD = 20
MIN_TIME_THREASHOLD = 0.5


class BaseRPCShot(object):
    __metaclass__ = ABCMeta

    def __init__(self, username, password, domain, ts, iface_uuid, destination=None, target=None, dest_port=None,
                 target_port=None, state_exception_open=None, state_exception_closed=None, auth_level=None,
                 lower_threshold=FILTERED_TIME_THRESHOLD, upper_threshold=UPPER_TIME_THRESHOLD,
                 min_threshold=MIN_TIME_THREASHOLD):
        self.destination = destination if destination else DEFAULT_HOST
        self.target = target if target else DEFAULT_HOST
        self.dest_port = dest_port if dest_port else DEFAULT_DEST_PORT
        self.trgt_port = target_port if target_port else DEFAULT_TRGT_PORT
        self.username = username
        self.password = password
        self.domain = domain
        self.results = []
        self.dce = None
        self.rpcTransport = None
        self.state_open_exception = state_exception_open
        self.state_closed_exception = state_exception_closed
        self.lower_threshold = lower_threshold
        self.upper_threshold = upper_threshold
        self.min_threshold = min_threshold
        self.iface_uuid = iface_uuid
        self.ts = ts
        self.auth_level = auth_level

    @abstractmethod
    def do_rpc_logic(self):
        pass

    @abstractmethod
    def do_binding(self):
        pass

    @staticmethod
    @abstractmethod
    def target_port_range():
        pass

    @staticmethod
    @abstractmethod
    def destination_port_range():
        pass

    def close(self):
        try:
            if self.rpcTransport:
                self.rpcTransport.disconnect()
        except Exception as err:
            pass

    def connect_and_bind(self):
        try:
            rpctransport = transport.DCERPCTransportFactory(self.do_binding())
            if hasattr(rpctransport, 'set_credentials'):
                rpctransport.set_credentials(self.username, self.password, self.domain, '', '')
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            self.rpcTransport = rpctransport
            if self.auth_level:
                dce.set_auth_level(self.auth_level)

            dce.bind(self.iface_uuid, transfer_syntax=self.ts)
            self.dce = dce
        except Exception as err:
            logger.debug(f'{type(self).__name__} - Connection failed for {self.destination}->{self.target}:{self.trgt_port} - {err}')

    def shoot(self):
        err = None
        state = PORT_UNKNOWN
        self.connect_and_bind()
        elapsed = 0
        if self.dce:
            start = time.time()
            try:
                self.do_rpc_logic()
            except DCERPCException as e:
                err = e
            except Exception as e:
                err = e
            finally:
                self.close()

                elapsed = time.time() - start
                if elapsed < self.min_threshold:
                    state = PORT_UNKNOWN
                    if err and self.state_open_exception:
                        for open_exp_str in self.state_open_exception:
                            if open_exp_str in str(err):
                                state = PORT_OPEN
                                break
                elif elapsed < self.lower_threshold:
                    state = PORT_OPEN
                    if err and self.state_closed_exception:
                        for closed_exp_str in self.state_closed_exception:
                            if closed_exp_str in str(err):
                                state = PORT_CLOSED
                                break
                elif elapsed < self.upper_threshold:
                    state = PORT_FILTERED
                else:
                    state = PORT_OPEN

        logger.debug(f'{type(self).__name__} - determined {state} for {self.destination}->{self.target}:{self.trgt_port} after {round(elapsed,2)} seconds - with error: {err}')
        logger.info(f'{type(self).__name__} - {self.destination}->{self.target}:{self.trgt_port} - {state}')
        return self.destination, self.target, self.trgt_port, state

        logger.debug(f'{type(self).__name__} - failed RPC connection')