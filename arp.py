import struct
from utils import b2ip, b2mac
from protocol import Protocol
from log import log


class ARP(Protocol):
    protocol = 'ARP'

    def parse(self):
        self.h_type = self._read('>H')
        self.p_type = self._read('>H')
        self.h_length = self._read('B')
        self.p_length = self._read('B')
        assert self.h_type == 1 and self.h_length == 6, 'Invalid hardware type'
        assert self.p_type == 0x0800 and self.p_length == 4, 'Invalid protocol type'

        self.op = self._read('>H')
        if self.op == 1:
            pass # arp request
        elif self.op == 2:
            pass # arp response
        elif self.op == 3:
            pass # rarp request
        elif self.op == 4:
            pass # rarp response
        else:
            raise Exception('Invalid arp operation: %04X' % self.op)

        self.src_mac = self._read('6B')
        self.src_ip = self._read('4B')
        self.dst_mac = self._read('6B') 
        self.dst_ip = self._read('4B')
        path = (
            '%s %s' % (b2mac(self.src_mac), b2ip(self.src_ip)),
            '%s %s' % (b2mac(self.dst_mac), b2ip(self.dst_ip)),
        )
        log(self.deep, 'arp', path, '%04X %04X' % (self.h_type, self.p_type))
