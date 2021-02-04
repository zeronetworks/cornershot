import queue
import threading
import time
from random import uniform,shuffle

from .shots import PORT_UNKNOWN,PORT_FILTERED
from .shots.even import EVENShot
from .shots.even6 import EVEN6Shot
from .shots.rprn import RPRNShot
from .shots.rrp import RRPShot

from . import logger

MAX_QUEUE_SIZE = 1000
TARGET_PORTS = [135, 445, 3389, 5985, 5986]

DEFAULT_SHOTS = [EVENShot, RPRNShot, RRPShot, EVEN6Shot]

class CornerShot(object):
    def __init__(self, username, password, domain, workers=250, shots=None):

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
        self.shot_list = []
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
                        logger.debug(f'Timeout error')
                    except Exception:
                        logger.debug(f'Unexpected exception during shot', exc_info=True)
                    finally:
                        self.bulletQ.task_done()
                        self.resultQ.put(res)
            except (queue.Empty,TimeoutError):
                pass
            except Exception:
                logger.debug(f'Unexpected exception during bullet load', exc_info=True)

    def add_shots(self, destinations, targets, target_ports=None, destination_ports=None):

        if target_ports is None:
            target_ports = TARGET_PORTS

        self._shots_generator(destinations, targets, target_ports, destination_ports)

    def add_many_shot_pairs(self, carrier_target_pairs, target_ports=None, destination_ports=None):
        if target_ports is None:
            target_ports = TARGET_PORTS

        tport_shot_class = []
        for target_port in target_ports:
            tport_shot_class.append([target_port,self._get_suitable_shots(target_port, destination_ports)])

        for ct_pair in carrier_target_pairs:
            carrier = ct_pair[0]
            target = ct_pair[1]
            for tport_shot_class_pair in tport_shot_class:
                target_port = tport_shot_class_pair[0]
                for cls in tport_shot_class_pair[1]:
                    self.shot_list.append(cls(self.username, self.password, self.domain, carrier, target,target_port=target_port))

    def _shots_generator(self, destinations, targets, target_ports, destination_ports=None):
        for destination in destinations:
            for target in targets:
                for target_port in target_ports:
                    for cls in self._get_suitable_shots(target_port, destination_ports):
                        self.shot_list.append(cls(self.username, self.password, self.domain, destination, target,target_port=target_port))

    def _merge_result(self, dest, target, tport, state):
        if dest not in self.results:
            self.results[dest] = {}
        if target not in self.results[dest]:
            self.results[dest][target] = {}
        if tport not in self.results[dest][target]:
            self.results[dest][target][tport] = state
        elif PORT_UNKNOWN in self.results[dest][target][tport]:
            self.results[dest][target][tport] = state
        elif PORT_FILTERED in self.results[dest][target][tport]:
            pass
        elif PORT_FILTERED in state:
            self.results[dest][target][tport] = state
        elif PORT_UNKNOWN in state:
            pass
        elif state not in self.results[dest][target][tport]:
            self.results[dest][target][tport] += "|" + state

    def _shots_manager(self):
        remaining = MAX_QUEUE_SIZE
        while self.runthreads:
            new_tasks = self.shot_list[0:remaining]
            self.shot_list = self.shot_list[remaining + 1:]
            tasks = new_tasks
            shuffle(tasks)

            remaining = remaining - len(tasks)

            for bt in tasks:
                time.sleep(uniform(0, 0.026))
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
                        self.resultQ.task_done()
                        remaining += 1
                        self.total_shots -= 1
                        if self.total_shots < 1:
                            self.runthreads = False
                    break

        self.total_shots = 0

    def open_fire(self,blocking=True):
        num_threads = min(self.total_shots,self.workers)

        if self.total_shots > 0:
            for _ in range(num_threads):
                w = threading.Thread(target=self._takeashot, daemon=True)
                w.start()
        if blocking:
            self._shots_manager()
            return self.results
        else:
            main_thread = threading.Thread(target=self._shots_manager,daemon=True)
            main_thread.start()

    def read_results(self):
        return self.results

    def lock_and_load(self):
        self.total_shots = self.remaining_shots()

    def remaining_shots(self):
        return len(self.shot_list)

    def _get_suitable_shots(self, target_port, destination_port):
        class_list = []
        for bc in self.shot_classes:
            if destination_port:
                if destination_port in bc.destination_port_range() and target_port in bc.target_port_range():
                    class_list.append(bc)
            elif target_port in bc.target_port_range():
                class_list.append(bc)

        return class_list

