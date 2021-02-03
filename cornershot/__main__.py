from argparse import ArgumentParser
import re
from ipaddress import ip_network, AddressValueError, NetmaskValueError, summarize_address_range, ip_address,collapse_addresses
from .cornershot import CornerShot
from . import logger
import logging
from json import dumps

DEFAULT_NUM_THREADS = 200
DEFAULT_TARGET_PORTS = [135, 445, 3389, 5985, 5986]

INVALID_SUBNET_ERROR_MESSAGE = f"please pick a valid comma delimited list of ip subnet or range such as '192.168.10.0/24,10.9.0.0-10.9.0.255'"
INVALID_PORTS_ERROR_MESSAGE = f"please pick a valid comma delimited list of port ranges, or list of ports"


def parse_args():
    parser = ArgumentParser(prog="CornerShot", prefix_chars="-/", add_help=False, description=f'Corner Shooter')

    parser.add_argument('-h', '--help', '/?', '/h', '/help', action='help', help='show this help message and exit')
    parser.add_argument("user", help="provide any authenticated user in the domain", type=str)
    parser.add_argument("password", help="domain password", type=str)
    parser.add_argument("domain", help="the FQDN of the domain.", type=str)
    parser.add_argument("carrier", help="carrier host for cornershot", type=str)
    parser.add_argument("target", help="target for shot", type=str)
    parser.add_argument("-tp", "--tports", dest='tports', default=DEFAULT_TARGET_PORTS, help="comma delimited list of target port ranges to scan for", type=str)
    parser.add_argument("-w", "--workerthreads", dest='threads', help="number of threads to perform shots", default=DEFAULT_NUM_THREADS, type=int)
    parser.add_argument('-v', dest='verbose', action='store_true', help='enable verbose logging')

    args = parser.parse_args()

    return args


def set_logger(is_verbose):
    log_level = logging.DEBUG if is_verbose else logging.INFO

    logger.setLevel(log_level)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)

    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)


def parse_ip_ranges(ip_ranges):
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
                    for ipnet in summarize_address_range(ip_address(first_addr), ip_address(last_addr)):
                        add_list += [ipad.exploded for ipad in ipnet]
                elif '/' in address:
                    add_list += [ipad.exploded for ipad in ip_network(address, strict=False)]
                else:
                    add_list.append(address)

    except (AddressValueError, NetmaskValueError, ValueError):
        raise ValueError(INVALID_SUBNET_ERROR_MESSAGE)

    return add_list


def parse_port_ranges(ranges):
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


if __name__ == '__main__':
    try:
        cs = None
        args = parse_args()
        set_logger(args.verbose)
        logger.info('CornerShot starting...')

        cs = CornerShot(args.user, args.password, args.domain, workers=args.threads)
        cs.add_shots(parse_ip_ranges(args.carrier), parse_ip_ranges(args.target), target_ports=parse_port_ranges(args.tports))
        cs.lock_and_load()
        cs.open_fire()

    except KeyboardInterrupt:
        logger.info("Interrupted!")
    except Exception as err:
        logger.error(f"CornerShot got exception - {err}")
        logger.debug(f"CornerShot unexpected exception!", exc_info=True)
    finally:
        logger.info('CornerShot finished...')
        if cs:
            res = cs.read_results()
            if res: logger.info(dumps(res,indent=4))
