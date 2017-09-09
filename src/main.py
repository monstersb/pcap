#! /usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import sys

from pcap import Pcap
from protocol.ethernet import Ethernet

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', help='show detail')
    parser.add_argument('-i', '--input', action='store_true', help='read from stdin')
    parser.add_argument('-f', '--file', action='store', help='read from file')
    parser.add_argument('-I', '--interface', action='store', help='read from interface')
    opt = parser.parse_args()
    if opt.input:
        stream = sys.stdin
    elif opt.file:
        stream = open(opt.file, 'rb')
    else:
        exit()

    pcap = Pcap(stream)
    while True:
        sec, msec, length, frame = pcap.read()
        ethernet = Ethernet(None, frame)
        ethernet.parse()
        if opt.verbose:
            print('time: %d.%d' % (sec, msec))
            ethernet.verbose()
            print()
