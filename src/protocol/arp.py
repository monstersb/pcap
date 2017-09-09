from .protocol import Protocol
from utils import b2ip, b2mac, color, btable

arp_op = btable({
    1: 'ARP Request',
    2: 'ARP Response',
    3: 'RARP Request',
    4: 'RARP Response'
})

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
        if self.op in arp_op:
            pass
        else:
            raise Exception('Invalid arp operation: %04X' % self.op)

        self.src_mac = self._read('6B')
        self.src_ip = self._read('4B')
        self.dst_mac = self._read('6B') 
        self.dst_ip = self._read('4B')

    @property
    def src_ip(self, raw=False):
        return self._src_ip if raw else b2ip(self._src_ip)

    @src_ip.setter
    def src_ip(self, x):
        self._src_ip = x

    @property
    def dst_ip(self, raw=False):
        return self._dst_ip if raw else b2ip(self._dst_ip)

    @dst_ip.setter
    def dst_ip(self, x):
        self._dst_ip = x

    @property
    def src_mac(self, raw=False):
        return self._src_mac if raw else b2mac(self._src_mac)

    @src_mac.setter
    def src_mac(self, x):
        self._src_mac = x

    @property
    def dst_mac(self, raw=False):
        return self._dst_mac if raw else b2mac(self._dst_mac)

    @dst_mac.setter
    def dst_mac(self, x):
        self._dst_mac = x

    def __str__(self):
        if arp_op[self.op] == 'ARP Request':
            action = 'Who has %s' % color(self.src_ip, 'blue')
        elif arp_op[self.op] == 'ARP Response':
            action = '%s is at %s' % (color(self.src_ip, 'blue'), color(self.src_mac, 'blue'))
        else:
            action = ''
        return '[%s] (%s) from:[%s %s] %s' % (
            color(self.protocol, 'cyan'),
            color(arp_op[self.op], 'green'),
            color(self.src_mac, 'yellow'),
            color(self.src_ip, 'yellow'),
            action
        )
