import argparse
import nmap
from socket import *

def connScan(tgtHost, tgtPort): 
    try: 
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('ViolentPython\r\n')
        results = connSkt.recv(100)
        print('[+]%d/tcp open'% tgtPort)
        print('[+] ' + str(results))
        connSkt.close()
    except: 
        print('[-]%d/tcp closed'% tgtPort)

def portScan(tgtHost, tgtPorts): 
    try: 
        tgtIP = gethostbyname(tgtHost)
    except: 
        print("[-]Cannot resolve '%s': Unknown host"% tgtHost)
        return

    try:
        tgtName = gethostbyaddr(tgtIP)
        print('\n[+] Scan results for: ' + tgtName[0])
    except: 
        print('\n[+] Scan results for: ' + tgtIP)
    setdefaulttimeout(1)

    for tgtPort in tgtPorts:
        # t = thread.start_new_thread(connScan, (tgtHost, int(tgtPort)))
        print('Scanning port ' + tgtPort)
        connScan(tgtHost, int(tgtPort))

def nmapScan(tgtHost, tgtPort):
    nmscan = nmap.PortScanner()
    nmscan.scan(tgtHost, tgtPort)
    try:
        state = nmscan[tgtHost]['tcp'][int(tgtPort)]['state']
        print(' [*] ' + tgtHost + ' tcp/' + tgtPort + ' ' + state)
    except KeyError as e:
        print(e)
        print('The specified IP address is unreachable')
        exit()

def main(): 
    parser = argparse.ArgumentParser(usage='-H <target host> -p <target port>')

    parser.add_argument('-H', dest='tgtHost', type=str, help='specify target host')
    parser.add_argument('-p', dest='tgtPort', type=str, help='specify target port(s) separated by comma')
    args = parser.parse_args()

    tgtHost = args.tgtHost
    tgtPorts = str(args.tgtPort).split(', ')

    if (tgtHost == None)|(tgtPorts[0] == None): 
        print(parser.usage)
        exit(0)
    for tgtPort in tgtPorts:
        nmapScan(tgtHost, tgtPort)
        #portScan(tgtHost, tgtPorts)
if __name__ == '__main__':
    main()