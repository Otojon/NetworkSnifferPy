#!/usr/bin/python3

import argparse
from scapy.all import *
# Scapy helps us to code helps making lower level automated tools for us.It's  interactive packet manipulation program


class Snifff:
    def __call__(self, packet):
        if self.args.verbose:
            packet.show()
        else:
            print(packet.summary())
    
    def __init__(self, args):
        self.args = args
    
    def loop(self):  # to keep sniffing without stop 
        sniff(iface=self.args.interface, prn=self, store=0)


if __name__ == "__main__":
    p= argparse.ArgumentParser()
    p.add_argument('-v', '--verbose', default=False,action='store_true')
    p.add_argument('-i', '--interface', type=str, required=True, help='network interface name')
    args = p.parse_args()
    sniffer = Snifff(args)
    sniffer.loop()