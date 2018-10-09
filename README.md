# pscan
A simple port scanner written in python3
```
$ ./pscan.py -h

Usage: pscan.py -H <target_host> -p <target_port / port_range>

Options:
  -h, --help       show this help message and exit
  -H TARGET_HOST   specify a target host
  -p TARGET_PORTS  specify a target port[s] / port range :
  -t TIMEOUT       specify a timeout (seconds) to wait on socket connection.
                   Connections that take longer than this are considered
                   closed (DEFAULT: 1s)

Examples:
     ./pscan.py -H example.com -p 80
     ./pscan.py -H example.com -p 80,443
     ./pscan.py -H example.com -p 1-100
     ./pscan.py -H example.com -p 1-100,443 -t 2
```
