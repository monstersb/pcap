from .protocol import Protocol
from utils import b2ip, color


class IP(Protocol):
    protocol = 'IP'

    def parse(self):
        t = self._read('B')
        self.version = (t & 0b11110000) >> 4
        self.header_length = ((t & 0b1111) >> 4) * 4
        self.tos = self._read('B')
        self.length = self._read('>H')
        self.identification = self._read('>H')
        t = self._read('>H')
        self.allow_fragment = not (t & 0b010)
        self.more_fragment = bool(t & 0b001)
        self.frament_offset = t >> 3
        self.ttl = self._read('B')
        self.proto = self._read('B')
        self.crc = self._read('>H')
        self.src = self._read('4B')
        self.dst = self._read('4B')

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
