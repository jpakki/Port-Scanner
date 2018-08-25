import argparse

parser = argparse.ArgumentParser(usage='-H <target host> -p <target port>')
parser.add_argument('-H', dest='tgtHost', type=str, help='specify target host')
parser.add_argument('-p', dest='tgtPort', type=int, help='specify target port')
args = parser.parse_args()

tgtHost = args.tgtHost
tgtPort = args.tgtPort

if (tgtHost == None)| (tgtPort == None): 
    print parser.usage
#print args.tgtHost