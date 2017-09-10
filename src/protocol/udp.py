from .protocol import Protocol
from utils import color



class UDP(Protocol):
    protocol = 'UDP'

    def parse(self):
        assert len(self._data) >= 8, 'invalid UDP Header'
        self.src = self._read('>H')
        self.dst = self._read('>H')
        self.length = self._read('>H')
        self.crc = self._read('>H')

    def __str__(self):
        return '[%s] [%s -> %s] Length:%d' % (
                color(self.protocol, 'cyan'), 
                color(self.src, 'yellow'),
                color(self.dst, 'yellow'),
                self.length
        )
