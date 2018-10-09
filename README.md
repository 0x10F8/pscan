# pscan
A simple port scanner written in python3
<br>
$ ./pscan.py -h
<br>
Usage: pscan.py -H <target_host> -p <target_port / port_range>
<br><br>
Options:<br>
  -h, --help       show this help message and exit<br>
  -H TARGET_HOST   specify a target host<br>
  -p TARGET_PORTS  specify a target port[s] / port range :<br>
  -t TIMEOUT       specify a timeout (seconds) to wait on socket connection.<br>
                   Connections that take longer than this are considered<br>
                   closed (DEFAULT: 1s)<br>
<br><br>
Examples:<br>
     ./pscan.py -H example.com -p 80<br>
     ./pscan.py -H example.com -p 80,443<br>
     ./pscan.py -H example.com -p 1-100<br>
     ./pscan.py -H example.com -p 1-100,443 -t 2<br>
