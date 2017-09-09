from .protocol import Protocol
from .ip import IP
from .arp import ARP
from utils import b2mac, btable, color


frame_type = btable({
    0x0800: 'IP',
    0x0806: 'ARP',
    0x0835: 'RARP',
})


class Ethernet(Protocol):
    protocol = 'Ethernet'

    def parse(self):
        assert len(self._data) >= 14, 'invalid ethernet frame'
        self.src = self._read('6B')
        self.dst = self._read('6B')
        self.data_type = self._read('>H')

        if frame_type[self.data_type] == 'IP':
            ip = IP(self, self._data[self._pos:])
            ip.parse()
            self.child.append(ip)
        elif frame_type[self.data_type] in ('ARP', 'RARP'):
            arp = ARP(self, self._data[self._pos:])
            arp.parse()
            self.child.append(arp)
        else:
            raise Exception('Unrecognize frame type %04X' % self.data_type)

    def __str__(self):
        return '[%s] [%s -> %s]' % (
                color(self.protocol, 'cyan'), 
                color(b2mac(self.src), 'yellow'),
                color(b2mac(self.dst), 'yellow')
        )
