from .protocol import Protocol
from utils import b2ip, b2mac, color


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

    def __str__(self):
        return '[%s] [%s -> %s] [%s -> %s]' % (
            color(self.protocol, 'cyan'),
            color(b2mac(self.src_mac), 'yellow'),
            color(b2mac(self.dst_mac), 'yellow'),
            color(b2ip(self.src_ip), 'yellow'),
            color(b2ip(self.dst_ip), 'yellow')
        )
