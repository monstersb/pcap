from .protocol import Protocol
from utils import b2ip, b2mac, color, btable

icmp_type = btable({
    0: 'Echo Reply',
    3: 'Destination Unreachable',
    4: 'Source Quench',
    5: 'Redirect Message',
    8: 'Echo Request',
    9: 'Router Advertisement',
    10: 'Router Solicitation',
    11: 'Time Exceeded',
    12: 'Parameter Problem: Bad IP header',
    13: 'Timestamp',
    14: 'Timestamp Reply',
    15: 'Information Request',
    16: 'Information Reply',
    17: 'Address Mask Request',
    18: 'Address Mask Reply',
    30: 'Traceroute',
})

icmp_code = btable({
    '0.0': '',
    '3.0': 'Destination network unreachable',
    '3.1': 'Destination host unreachable',
    '3.2': 'Destination protocol unreachable',
    '3.3': 'Destination port unreachable',
    '3.4': 'Fragmentation required, and DF flag set',
    '3.5': 'Source route failed',
    '3.6': 'Destination network unknown',
    '3.7': 'Destination host unknown',
    '3.8': 'Source host isolated',
    '3.9': 'Network administratively prohibited',
    '3.10': 'Host administratively prohibited',
    '3.11': 'Network unreachable for ToS',
    '3.12': 'Host unreachable for ToS',
    '3.13': 'Communication administratively prohibited',
    '3.14': 'Host Precedence Violation',
    '3.15': 'Precedence cutoff in effect',
    '4.0': '',
    '5.0': 'Redirect Datagram for the Network',
    '5.1': 'Redirect Datagram for the Host',
    '5.2': 'Redirect Datagram for the ToS & network',
    '5.3': 'Redirect Datagram for the ToS & host',
    '8.0': '',
    '9.0': '',
    '10.0': '',
    '11.0': 'TTL expired in transit',
    '11.1': 'Fragment reassembly time exceeded',
    '12.0': 'Pointer indicates the error',
    '12.1': 'Missing a required option',
    '12.2': 'Bad length',
    '13.0': '',
    '14.0': '',
    '15.0': '',
    '16.0': '',
    '17.0': '',
    '18.0': '',
    '30.0': '',
})

class ICMP(Protocol):
    protocol = 'ICMP'

    def parse(self):
        self.type = self._read('B')
        self.code = self._read('B')
        assert '%d.%d' % (self.type, self.code) in icmp_code, 'Unrecognized ICMP type'
        self.crc = self._read('>H')

    def __str__(self):
        return '[%s] (%s) %s' % (
            color(self.protocol, 'cyan'),
            color(icmp_type[self.type], 'green'),
            icmp_code['%d.%d' % (self.type, self.code)]
        )
