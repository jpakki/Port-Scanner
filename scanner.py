import argparse
from socket import *

parser = argparse.ArgumentParser(usage='-H <target host> -p <target port>')

parser.add_argument('-H', dest='tgtHost', type=str, help='specify target host')
parser.add_argument('-p', dest='tgtPort', type=int, help='specify target port')
args = parser.parse_args()

tgtHost = args.tgtHost
tgtPort = args.tgtPort

if (tgtHost == None)|(tgtPort == None): 
    print parser.usage
    exit(0)

def connScan(tgtHost, tgtPort): 
    try: 
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('ViolentPython\r\n')
        results = connSkt.recv(100)
        print '[+]%d/tcp open'% tgtPort
        print '[+] ' + str(results)
        connSkt.close()
    except: 
        print '[-]%d/tcp closed'% tgtPort

def portScan(tgtHost, tgtPorts): 
    try: 
        tgtIP = gethostbyname(tgtHost)
    except: 
        print "[-]Cannot resolve '%s': Unknown host"% tgtHost
        return

    try:
        tgtName = gethostbyaddr(tgtIP)
        print '\n[+] Scan results for: ' + tgtName[0]
    except: 
        print '\n[+] Scan results for: ' + tgtIP
    setdefaulttimeout(1)

    for tgtPort in tgtPorts:
        print 'Scanning port ' + tgtPort
        connScan(tgtHost, int(tgtPort))

def main(): 
    