from .protocol import Protocol
from .icmp import ICMP
from utils import b2ip, color, btable

ip_protocol = btable({
    0x01: 'ICMP',
    0x06: 'TCP',
    0x11: 'UDP'
})


class IP(Protocol):
    protocol = 'IP'

    def parse(self):
        t = self._read('B')
        self.version = (t & 0b11110000) >> 4
        self.header_length = (t & 0b1111) * 4
        self.tos = self._read('B')
        self.length = self._read('>H')
        self.identification = self._read('>H')
        t = self._read('>H')
        self.allow_fragment = not (t & 0x40)
        self.more_fragment = bool(t & 0x20)
        self.frament_offset = t & 0x1F
        self.ttl = self._read('B')
        self.proto = self._read('B')
        assert self.proto in ip_protocol, 'Unrecongnized IP type %02X' % self.proto
        self.crc = self._read('>H')
        self.src = self._read('4B')
        self.dst = self._read('4B')
        self.option = self._read('%dB' % (self.header_length - 20))

        if ip_protocol[self.proto] == 'ICMP':
            icmp = ICMP(self, self._data[self._pos:])
            icmp.parse()
            self.child.append(icmp)
        else:
            pass

    @property
    def src(self, raw=False):
        return self._src if raw else b2ip(self._src)

    @src.setter
    def src(self, x):
        self._src = x

    @property
    def dst(self, raw=False):
        return self._dst if raw else b2ip(self._dst)

    @dst.setter
    def dst(self, x):
        self._dst = x

    def __str__(self):

        if self.allow_fragment:
            fragment = 'Fragment:[%s%s]' % (
                color(hex(self.frament_offset), 'blue'),
                '' if self.more_fragment else ' Last',
            )
        else:
            fragment = ''
        return '[%s] (%s) [%s -> %s] TTL:%s ID:%s %s' % (
            color(self.protocol, 'cyan'),
            color('IPv%d' % self.version, 'green'),
            color(self.src, 'yellow'),
            color(self.dst, 'yellow'),
            color(self.ttl, 'blue'),
            color(hex(self.identification), 'blue'),
            fragment
        )
