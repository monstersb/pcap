import struct
from utils import b2ip
from protocol import Protocol
from log import log


class IP(Protocol):
    protocol = 'IP'

    def parse(self):
        t = self._read('B')
        self.version = (t & 0b11110000) >> 4
        self.header_length = ((t & 0b1111) >> 4) * 4
        self.tos = self._read('B')
        self.length = self._read('>H')
        self.ser = self._read('>H')
        t = self._read('>H')
        self.flag = t & 0b111
        self.offset = t >> 3
        self.ttl = self._read('B')
        self.proto = self._read('B')
        self.crc = self._read('>H')
        self.src = self._read('4B')
        self.dst = self._read('4B')
        path = (b2ip(self.src), b2ip(self.dst))
        log(self.deep, 'ipv%d' % self.version, path, 'Protocol:%02X TTL:%d' % (self.proto, self.ttl))
