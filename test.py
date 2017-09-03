#! /usr/bin/env python

from pcap import Pcap

with open('sample.pcap', 'rb') as f:
    pcap = Pcap(f)
    while True:
        print(pcap.read())
