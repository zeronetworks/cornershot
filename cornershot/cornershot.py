import itertools
import queue
import re
import threading
import time
from ipaddress import ip_network, AddressValueError, NetmaskValueError, summarize_address_range, ip_address

from .shots import PORT_UNKNOWN
from .shots.even import EVENShot
from .shots.even6 import EVEN6Shot
from .shots.rprn import RPRNShot
from .shots.rrp import RRPShot

from . import logger

MAX_QUEUE_SIZE = 1000
TARGET_PORTS = [135, 445, 3389, 5985, 5986]

DEFAULT_SHOTS = [EVENShot, RPRNShot, RRPShot, EVEN6Shot]

INVALID_SUBNET_ERROR_MESSAGE = f"please pick a valid comma delimited list of ip subnet or range such as '192.168.10.0/24,10.9.0.0-10.9.0.255'"
INVALID_PORTS_ERROR_MESSAGE = f"please pick a valid comma delimited list of port ranges, or list of ports"


class CornerShot(object):
    def __init__(self, username, password, domain, workers=20, shots=None):

        logger.debug(f'CS created with username: {username},domain:{domain},workers:{workers}')
        if shots is None:
            shots = DEFAULT_SHOTS

        self.shot_classes = shots
        self.username = username
        self.password = password
        self.domain = domain
        self.workers = workers
        self.bulletQ = queue.Queue()
        self.resultQ = queue.Queue()
        self.runthreads = True
        self.results = {}
        self.shot_gen = None
        self.total_shots = 0

    def _takeashot(self):
        while self.runthreads:
            res = None
            try:
                bullet = self.bulletQ.get(timeout=0.1)
                if bullet:
                    try:
                        res = bullet.shoot()
                    except TimeoutError:
                        logger.debug(f'Timeout error', exc_info=True)
                    except Exception:
                        logger.debug(f'Unexpected exception during shot', exc_info=True)
                    finally:
                        self.bulletQ.task_done()
                        self.resultQ.put(res)
            except TimeoutError:
                pass
            except Exception:
                logger.debug(f'Unexpected exception during bullet load', exc_info=True)

    def add_shots(self, destinations, targets, target_ports=None, destination_ports=None):

        if target_ports is None:
            target_ports = TARGET_PORTS

        dests = CornerShot._parse_ip_ranges(destinations)
        targets = CornerShot._parse_ip_ranges(targets)
        tports = CornerShot._parse_port_ranges(target_ports)
        dports = None
        if destination_ports:
            dports = CornerShot._parse_port_ranges(destination_ports)

        if self.shot_gen:
            self.shot_gen = itertools.chain(self.shot_gen, self._shots_generator(dests, targets, tports, dports))
        else:
            self.shot_gen = self._shots_generator(dests, targets, tports, dports)

        # TODO maybe use a list
        self.shot_gen, sg_sum = itertools.tee(self.shot_gen)
        self.total_shots = sum(1 for _ in sg_sum)

    def _shots_generator(self, destinations, targets, target_ports, destination_ports=None):
        for destination in destinations:
            for target in targets:
                for target_port in target_ports:
                    for cls in self._get_suitable_shots(target_port, destination_ports):
                        yield cls(self.username, self.password, self.domain, destination, target,
                                  target_port=target_port)

    def _merge_result(self, dest, target, tport, state):
        if dest not in self.results:
            self.results[dest] = {}
        if target not in self.results[dest]:
            self.results[dest][target] = {}
        if tport not in self.results[dest][target]:
            self.results[dest][target][tport] = state
        elif PORT_UNKNOWN in self.results[dest][target][tport]:
            self.results[dest][target][tport] = state
        elif PORT_UNKNOWN in state:
            pass
        elif state not in self.results[dest][target][tport]:
            self.results[dest][target][tport] += "|" + state

    def open_fire(self):
        remaining = MAX_QUEUE_SIZE
        thread_list = []

        for _ in range(self.workers):
            w = threading.Thread(target=self._takeashot, daemon=True)
            w.start()
            thread_list.append(w)

        while self.runthreads:
            new_tasks = itertools.islice(self.shot_gen, remaining)
            tasks = list(new_tasks)

            remaining = remaining - len(tasks)

            for bt in tasks:
                self.bulletQ.put(bt)

            while True:
                if self.resultQ.empty():
                    time.sleep(0.3)
                else:
                    while not self.resultQ.empty():
                        result = self.resultQ.get()
                        if result:
                            destination, target, target_port, state = result
                            self._merge_result(destination, target, target_port, state)
                            logger.info(f"{destination}->{target}:{target_port} - {state}")
                        self.resultQ.task_done()
                        remaining += 1
                        self.total_shots -= 1
                        if self.total_shots < 1:
                            self.runthreads = False
                    break

        self.shot_gen = None
        self.total_shots = 0

        return self.results

    def _get_suitable_shots(self, target_port, destination_port):
        class_list = []
        for bc in self.shot_classes:
            if destination_port:
                if destination_port in bc.destination_port_range() and target_port in bc.target_port_range():
                    class_list.append(bc)
            elif target_port in bc.target_port_range():
                class_list.append(bc)

        return class_list

    @staticmethod
    def _parse_ip_ranges(ip_ranges):
        add_list = []
        try:
            if ip_ranges:
                if ',' in ip_ranges:
                    ip_ranges = ip_ranges.split(',')
                else:
                    ip_ranges = [ip_ranges]

                for address in ip_ranges:
                    if '-' in address:
                        first_addr = ip_address(address.split('-')[0])
                        last_addr = ip_address(address.split('-')[1])
                        add_list += [ipad.exploded for ipad in summarize_address_range(first_addr, last_addr)]
                    elif '/' in address:
                        add_list += [ipad.exploded for ipad in ip_network(address, strict=False).hosts()]
                    else:
                        add_list.append(address)

        except (AddressValueError, NetmaskValueError, ValueError):
            raise ValueError(INVALID_SUBNET_ERROR_MESSAGE)

        return add_list

    @staticmethod
    def _parse_port_ranges(ranges):
        port_ranges = []

        if type(ranges) is list:
            if all(isinstance(x, int) and (0 < x < 65536) for x in ranges):
                return ranges
            else:
                raise ValueError(INVALID_PORTS_ERROR_MESSAGE)

        if ranges:
            if ',' in ranges:
                ranges = ranges.split(',')
            else:
                ranges = [ranges]

            for port_range in ranges:
                res = re.findall(r"(\d+)-?(\d*)", port_range)
                if res:
                    pstart = int(res[0][0])
                    pend = None if not res[0][1] else int(res[0][1])
                    if pend:
                        port_ranges += [p for p in range(pstart, pend)]
                    else:
                        port_ranges.append(pstart)
                else:
                    raise ValueError(INVALID_PORTS_ERROR_MESSAGE)
        else:
            raise ValueError(INVALID_PORTS_ERROR_MESSAGE)

        return port_ranges
