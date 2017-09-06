#! /usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import sys
import colored

from pcap import Pcap
from ethernet import Ethernet

def logger(verbose):
    def log_null(*args):
        pass

    def color(bg, x):
        return colored.fg(bg) + x + colored.attr('reset')

    def log(protocol, path, data):
        protocol = color('yellow', '[%s]' % protocol)
        path = '(%s -> %s)' % (color('cyan', path[0]), color('cyan', path[1])) if path else ''
        print(protocol, path, data)

    return log if verbose else log_null


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
    pcap = Pcap(stream, log=logger(opt.verbose))
    while True:
        sec, msec, length, frame = pcap.read()
        Ethernet(frame, log=logger(opt.verbose))
