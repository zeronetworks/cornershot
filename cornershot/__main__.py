from argparse import ArgumentParser

from .cornershot import CornerShot
from . import logger
import logging

DEFAULT_NUM_THREADS = 200
DEFAULT_TARGET_PORTS = [135, 445, 3389, 5985, 5986]

def parse_args():
    parser = ArgumentParser(prog="CornerShot", prefix_chars="-/", add_help=False, description=f'Corner Shooter')

    parser.add_argument('-h', '--help', '/?', '/h', '/help', action='help', help='show this help message and exit')
    parser.add_argument("user", help="provide any authenticated user in the domain", type=str)
    parser.add_argument("password", help="domain password", type=str)
    parser.add_argument("domain", help="the FQDN of the domain.", type=str)
    parser.add_argument("destination", help="destination for cornershot", type=str)
    parser.add_argument("target", help="target for shot", type=str)
    parser.add_argument("-tp", "--tports", dest='tports',default=DEFAULT_TARGET_PORTS,help="comma delimited list of target port ranges to scan for", type=str)
    parser.add_argument("-w", "--workerthreads", dest='threads',help="number of threads to perform shots", default=DEFAULT_NUM_THREADS, type=int)

    args = parser.parse_args()

    return args

def set_logger():
    logger.setLevel(logging.INFO)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)


if __name__ == '__main__':
    try:
        set_logger()
        logger.info('CornerShot starting...')
        args = parse_args()
        cs = CornerShot(args.user, args.password, args.domain, workers=args.threads)
        cs.add_shots(args.destination, args.target,target_ports=args.tports)
        results = cs.open_fire()
        logger.info('Results -------')
        logger.info(results)

    except KeyboardInterrupt:
        logger.info("Interrupted!")
    except Exception as err:
        logger.info(f"CornerShot got exception - {err}")
        logger.error(f"CornerShot unexpected exception!",exc_info=True)
