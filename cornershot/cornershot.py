import itertools
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

        if self.shot_gen:
            self.shot_gen = itertools.chain(self.shot_gen, self._shots_generator(destinations, targets, target_ports, destination_ports))
        else:
            self.shot_gen = self._shots_generator(destinations, targets, target_ports, destination_ports)

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
        elif PORT_FILTERED in self.results[dest][target][tport]:
            pass
        elif PORT_FILTERED in state:
            self.results[dest][target][tport] = state
        elif PORT_UNKNOWN in state:
            passpy
        elif state not in self.results[dest][target][tport]:
            self.results[dest][target][tport] += "|" + state

    def open_fire(self):
        remaining = MAX_QUEUE_SIZE
        thread_list = []

        num_threads = min(self.total_shots,self.workers)

        if self.total_shots > 0:
            for _ in range(num_threads):
                w = threading.Thread(target=self._takeashot, daemon=True)
                w.start()
                thread_list.append(w)

            while self.runthreads:
                new_tasks = itertools.islice(self.shot_gen, remaining)
                tasks = list(new_tasks)
                shuffle(tasks)

                remaining = remaining - len(tasks)

                for bt in tasks:
                    time.sleep(uniform(0,0.026))
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

            self.shot_gen = None
            self.total_shots = 0

        return self.results

    def read_results(self):
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


