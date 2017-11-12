#!/usr/bin/python
from scapy.all import *
from random import randint
from time import sleep
from construct import *
import sys
import getopt
import re
import binascii

TVPacketData_Request = Struct(
	"syn" / Int32ub, 
	"ack" / Int32ub,
	"status" / Enum(Int16ub,
		Request=0x6440,
		Response=0x340d,
		Query=0x0000
	),
	"flag" / Enum(Int8ub,
		A=0x03,
		B=0x0b,
		C=0x1b,
		D=0x30
	),
	"signature" / Enum(Int16ub,
		Signature=0x1724,
	),
	"type" / Enum(Int8ub,
		A=0x6b,
		B=0x6f,
		C=0x40,
		D=0x6c,
		E=0x73,
		F=0x47
	),
	"length" / Int16ub,
)

Display = Struct(
	"opcode" / Enum(Int16ub,
		update=0x0c00
	),
	"max" / Enum(Int16ub,
		small=0x8000,
		equal=0x0000
	),
	"sequence" / Int32ub, 
	"option" / Enum(Int32ub,
		A=0x11000000,
		B=0x09000000,
		C=0x05000000
	)
)

def banner():
	print "==================================================="
	print "|               Simple_UDP_Fuzzer                 |"
	print "==================================================="

def usage():
	print >>sys.stderr, "[-] Simple_UDP_Fuzzer.py [-h|-p|-s|-S] -d dst_ip -D dst_port"
	print >>sys.stderr, "                         -h           : Help"
	print >>sys.stderr, "                         -p {tcp|udp} : TCP/UDP Protocol"
	print >>sys.stderr, "                         -s src_ip    : Source IP"
	print >>sys.stderr, "                         -S src_port  : Source Port"
	print >>sys.stderr, "                         -d dst_ip    : Destination IP"
	print >>sys.stderr, "                         -D dst_port  : Destination Port"
	sys.exit(-1)

def check_address(address):
	ip = None
	match = re.match("^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", address)
	if match:
		ip = match.group(1)
	else:
		print >>sys.stderr, "invalid address " + address 
	
	return ip

def get_random_data(n=16):
	return ''.join([chr(randint(0,255)) for i in xrange(n)])

def create_packet(protocol=None, src_ip=None, dst_ip=None, src_port=None, dst_port=None, max=1024):
    data_len = randint(0, max)
    print "[+] packet size : %u" % data_len
    data= get_random_data(data_len)
    data_len_little = (data_len << 8) if (data_len < 0xff) else ((data_len << 8) & 0xff00) + ((data_len) >> 8)
    data_len_little = (data_len_little - 0x10) & 0xffff

    status = ["Request", "Response", "Query"]
    flag = ["A", "B", "C", "D"]
    types = ["A", "B", "C", "D", "E", "F"]
    option = ["A", "B", "C"]

    if src_ip:
	packet = IP(src=src_ip, dst=dst_ip)
    else:
	packet = IP(dst=dst_ip)
	
    if protocol is None: protocol = 'tcp'
    if protocol == 'tcp':
    	if src_port:
	    packet = packet/TCP(sport=src_port, dport=dst_port)
	else:
	    packet = packet/TCP(dport=dst_port)
    elif protocol == 'udp':
	if src_port:
	    packet = packet/UDP(sport=src_port, dport=dst_port)
	else:
	    packet = packet/UDP(dport=dst_port)
    else:
	print "Unknown protocol"
	return None

    tv_header = TVPacketData_Request.build({
	"syn": 0x32000000,
	"ack": 0x64000000,
	"status": status[randint(0,len(status)-1)],
	"flag": flag[randint(0,len(flag)-1)],
	"signature": "Signature",
	"type": types[randint(0, len(types)-1)],
	"length": data_len_little    
    })
    display_header = Display.build({
	"opcode": "update",
	"max": "small" if (data_len >= 1024) else "equal",
	"sequence": 0x46000000,
	"option": option[randint(0, len(option)-1)]
    })
    packet = packet/tv_header/display_header/data

    print "[+] ==================== packet ===================="
    hexdump(packet)

    return packet

def fuzzing(netinfo):
    while True:
	packet = create_packet(**netinfo)

	with open("result.log", "w") as fh:
	   fh.write(str(packet))

	result = send(packet)
	sleep(1)

def check_netinfo(protocol=None, src_ip=None, dst_ip=None, src_port=None, dst_port=None, max=65000):
    if protocol != 'udp':
	return False
    if src_ip == None or dst_ip == None:
	return False
    if src_port == None or dst_port == None:
	return False
    if max == None or max == 0:
	return False

    return True

def config_netinfo():
	argv = sys.argv
	try:
		opts, args = getopt.getopt(argv[1:],
			"p:s:d:S:D:l:h",
			["protocol=", "src_ip=", "dst_ip=", "src_port=", "dst_port=", "length=", "help"])
	except getopt.error:
		usage()

	netinfo = {'protocol':'tcp'}
	for flag, value in opts:
		if flag in ['-p', '--protocol']:
			if value not in ['tcp', 'udp']:
				usage()
			netinfo['protocol'] = value
		elif flag in ['-s', '--src_ip']:
			netinfo['src_ip'] = check_address(value)
		elif flag in ['-d', '--dst_ip']:
			netinfo['dst_ip'] = check_address(value)
		elif flag in ['-S', '--src_port']:
			netinfo['src_port'] = int(value)
		elif flag in ['-D', '--dst_port']:
			netinfo['dst_port'] = int(value)
		elif flag in ['-l', '--length']:
			netinfo['length'] = int(value)
		elif flag in ['-h', '--help']:
			usage()
		else:
			usage()

	print "[+] Configured..."
	try:
	    if check_netinfo(**netinfo) == False: return None
	except:
	    usage()
	    return None

	return netinfo
"""
    	netinfo['src_mac'] = get_my_mac(netinfo['src_ip'])
	netinfo['dst_mac'] = get_target_mac(netinfo['src_mac'], netinfo['src_ip'], netinfo['dst_ip'])
	print "[+] my_mac : " + netinfo['src_mac']
	print "[+] dst_mac : " + netinfo['dst_mac']
"""

def main():
	banner()
	netinfo = config_netinfo()
	if netinfo != None:
	    fuzzing(netinfo)
	else:
	    print >>sys.stderr, "[-] Config Error..."
	    print >>sys.stderr, "[-] Please check arguments"
	    usage()

if __name__ == "__main__":
	main()

