#!/usr/bin/env python3

"""

Basic port scanner in python3

"""

# Imports
from socket import socket, AF_INET, SOCK_STREAM, gethostbyname
from optparse import OptionParser, IndentedHelpFormatter
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from pings import Ping

''' The minimum port number '''
MIN_PORT = 1
''' The maximum port number '''
MAX_PORT = 65535
''' All ports '''
ALL_PORT_RANGE = [i for i in range(MIN_PORT, MAX_PORT + 1)]

''' The number of pings to use to determine if a host is up (through ICMP pings) '''
HOST_UP_PING_COUNT = 1
''' Default timeout for various actions throughout the script '''
DEFAULT_TIMEOUT = 1
''' Default number of worker threads to use when port scanning '''
DEFAULT_WORKER_THREADS = 1000

# Configure the logger to info
logging.basicConfig(format="%(message)s", level=logging.INFO)


class InvalidPortError(Exception):
    """
    Raise this error when a port is outwith the ALL_PORT_RANGE limits
    """

    def __init__(self, port):
        self.port = port


class InvalidHostError(Exception):
    """
    Raise this error where a host name cannot be resolved
    """

    def __init__(self, host):
        self.host = host


class InvalidPortFormatError(Exception):
    """
    Raise this error if the port argument doesn't match the required format
    """

    def __init__(self, port_string):
        self.port_string = port_string


def is_host_up_icmp(host, timeout=DEFAULT_TIMEOUT):
    """
    Checks whether a host is up. If the host specified is a resolvable hostname rather than an IP address
    the method will first try to resolve the host name, if this fails an InvalidHostError will be raised.
    Next a single ping is sent to the host, and if this ping receives a valid response then the method
    returns True.

    Note that a host might have ICMP response disable so this cannot be taken as 100% accurate.

    :param host: The host to check
    :param timeout: The maximum time to wait on the ping response
    :return: Boolean True if the host responds to ping requests and has a valid host name tupled with the IP address
    """
    try:
        ip = gethostbyname(host)
    except:
        raise InvalidHostError(host)
    response = ping_host(host, timeout, HOST_UP_PING_COUNT)
    if response.packet_lost is None:
        return True, ip
    return False, None


def ping_host(host, timeout, count):
    """
    Sends ping requests to a host.

    :param host: The host to ping
    :param timeout: The maximum time to wait on a ping
    :param count: The number of pings to send
    :return: Response object containing the ping information
    """
    ping = Ping(timeout=(timeout * 1000))
    return ping.ping(host, count)


def is_port_open(host, port, timeout=DEFAULT_TIMEOUT):
    """
    Check if a specified remote host:port combination (socket) is listening.
    This will attempt to create a socket to the specified remote host and port, if the connection
    occurs then a tuple with the host, port and True should be returned almost instantly.
    The socket connection attempt will wait for the specified timeout (default 1 seconds) before
    returning a tuple with the host, port and False.

    :param host: The remote address
    :param port: The remote port
    :param timeout: The timeout to wait for the socket connection (default 1s optional)
    :return: A tuple in the format (host, port, is_open) where open is a boolean Value
    """
    logging.debug("Scanning port %d" % port)
    if port not in ALL_PORT_RANGE:
        raise InvalidPortError(port)
    try:
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            return host, port, True
    except:
        return host, port, False


def scan_port_range(host, ports, timeout=DEFAULT_TIMEOUT, worker_threads=DEFAULT_WORKER_THREADS):
    """
    Scan a port range on a host. This method will scan all of the ports in the ports list for the specified
    using the is_open(host, port, timeout) method. If the socket does not connect within the timeout specified
    it is marked as down. The process is multi-threaded and the maximum pool size is defined by the worker_threads
    parameter.

    :param host: The host to scan
    :param ports: The ports to scan on the host
    :param timeout: The timeout to wait until marking a port as down
    :param worker_threads: The maximum number of threads to pool to execute the work
    :return: Returns a list of tuples (host, port, is_open) where open is a Boolean value
    """
    thread_pool = ThreadPoolExecutor(max_workers=worker_threads)
    thread_results = []
    results = []
    for port in ports:
        thread_results.append(thread_pool.submit(is_port_open, host, port, timeout))
    for future in thread_results:
        results.append(future.result())
    thread_pool.shutdown()
    return results


def filter_results(results, filter_function):
    """
    Filter the results using a function on the result tuple.

    :param results: The results list
    :param filter_function: A function which acts upon a result tuple and returns True or False
    :return: A list of results tuples where filter_function(result) is true for each member
    """
    return [result for result in results if filter_function(result)]


def open_port_filter(result):
    """
    Returns true if the specified result tuple is for an open port.

    :param result: The result tuple (host, port, is_open)
    :return: True or False depending on the is_open flag
    """
    _, _, is_open = result
    return is_open


def parse_port_string(port_string):
    """
    This method will take a string of ports and port ranges from the passed user parameter and
    attempt to generate a list of port integers in order and without duplicates.

    :param port_string: The user input port string
    :return: list of int's containing the ports to scan
    """
    # Tokenize string by commas to find ranges
    tokenized_by_comma = port_string.split(',')

    # Find all port ranges (seperated by dashes) in tokenized values
    ranges = [token for token in tokenized_by_comma if '-' in token]

    # Find all non port ranges
    str_ports = [token for token in tokenized_by_comma if '-' not in token]

    # Add all string ports to the final port list and convert to ints
    try:
        ports = [int(port) for port in str_ports]
    except:
        # If the integer conversion failed then something weird was entered as a port
        raise InvalidPortFormatError(str_ports)

    # Convert string port ranges to the full list of int ports to scan
    for port_range in ranges:

        # Remove whitespace
        port_range_trim = port_range.replace(' ', '')
        # Tokenize by dash
        tokenized_by_dash = port_range_trim.split('-')

        # At this point we need to convert the range to integers and do some validation

        # If there is not 2 numbers in the range then the user has entered something weird!
        if len(tokenized_by_dash) != 2:
            raise InvalidPortFormatError(port_range)

        # If the 2 tokens are not integers then the user has entered something weird!
        try:
            from_port = int(tokenized_by_dash[0])
            to_port = int(tokenized_by_dash[1])
        except:
            raise InvalidPortFormatError(port_range)

        # If the from_port is not before the to_port then the user has entered something weird!
        if from_port >= to_port:
            raise InvalidPortFormatError(port_range)

        for port in range(from_port, to_port):
            ports.append(port)
    # remove duplicates (might be since ranges can overlap or duplicate ports in comma separated lists)
    ports = list(set(ports))

    # sort from lowest to highest
    ports.sort()

    return ports


def get_service(port):
    """
    TODO: implement a port to service mapping
    :param port: the port to get the service for
    :return: service name typically found on this port
    """
    return 'NYI'  # Not Yet Implemented


def pad_line(line, target_length, padding_char=' '):
    """
    Pad a line to the desired length
    :param line: The line to pad
    :param target_length: The target length
    :param padding_char: The padding char, defaults to space
    :return: The padded string
    """
    line = str(line)
    extra = target_length - len(line)
    padding = padding_char * extra
    return line + padding


def print_results(results):
    """
    Prints the results in a standard format and column length.
    :param results:  The results
    :return: nothing
    """
    # Setup target column count per header
    port_cols = 12
    state_cols = 9
    service_cols = 10

    # Setup headers
    port_header = pad_line("PORT", port_cols)
    state_header = pad_line("STATE", state_cols)
    service_header = pad_line("SERVICE", service_cols)

    # print header
    print(" %s%s%s" % (port_header, state_header, service_header))

    # print results
    for result in results:
        _, port, is_open = result
        service = get_service(port)
        print(" %s%s%s" % (pad_line(port, port_cols),
                           pad_line(("OPEN" if is_open else "CLOSED"), state_cols),
                           pad_line(service, service_cols)))


class PScanHelpFormatter(IndentedHelpFormatter):
    """Custom formatter to allow new lines in the epilog
    """

    def __init__(self,
                 indent_increment=2,
                 max_help_position=24,
                 width=None,
                 short_first=1):
        IndentedHelpFormatter.__init__(
            self, indent_increment, max_help_position, width, short_first)

    def format_epilog(self, epilog):
        if epilog:
            return "\n" + epilog + "\n"
        else:
            return ""


# Do option parsing
option_parser = OptionParser(usage="%prog -H <target_host> -p <target_port / port_range>",
                             formatter=PScanHelpFormatter())
option_parser.epilog = \
    """Examples:
     {0} -H example.com -p 80
     {0} -H example.com -p 80,443
     {0} -H example.com -p 1-100
     {0} -H example.com -p 1-100,443 -t 2
     """.format(sys.argv[0])

option_parser.add_option('-H', dest='target_host', type='string', help='specify a target host')
option_parser.add_option('-p', dest='target_ports', type='string', help='specify a target port[s] / port range :')
option_parser.add_option('-t', dest='timeout', type='int', default=DEFAULT_TIMEOUT,
                         help='specify a timeout (seconds) to wait on socket '
                              'connection. Connections that take longer than'
                              ' this are considered closed (DEFAULT: 1s)')
options, args = option_parser.parse_args()
target_host = options.target_host
target_port_string = options.target_ports
user_timeout = options.timeout

# Check arguments have been given
if target_host is None or target_port_string is None:
    print("You must specify a target host and port[s]")
    option_parser.print_usage()
    exit(0)

# Parse ports from string arguments
target_ports = parse_port_string(target_port_string)
if not (len(target_ports) > 0):
    logging.error("You must specify a target host and port[s]")
    option_parser.print_usage()
    exit(0)

# Check if the host is up (resolving the address if necessary) and output a relevant message
try:
    up, ip = is_host_up_icmp(target_host)
except InvalidHostError:
    print("Host %s could not be resolved" % target_host)
    exit(0)

if up:
    print("Host %s(%s) is up" % (target_host, ip))
else:
    print("Host %s is down or not responding to ICMP requests" % target_host)

# Do the port scanning
open_ports = filter_results(scan_port_range(target_host, target_ports, user_timeout), open_port_filter)

# Print the results
print_results(open_ports)
