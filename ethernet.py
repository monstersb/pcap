from protocol import Protocol
import struct
from ip import IP
from arp import ARP
from utils import b2mac, btable
from log import log


frame_type = btable({
    0x0800: 'IP',
    0x0806: 'ARP',
})


class Ethernet(Protocol):
    protocol = 'Ethernet'

    def parse(self):
        assert len(self._data) >= 14, 'invalid ethernet frame'
        self.src = self._read('6B')
        self.dst = self._read('6B')
        self.data_type = self._read('>H')
        log(self.deep, self.protocol, (b2mac(self.src), b2mac(self.dst)))
        if frame_type[self.data_type] == 'IP':
            ip = IP(self, self._data[14:])
            ip.parse()
        elif frame_type[self.data_type] == 'ARP':
            arp = ARP(self, self._data[14:])
            arp.parse()
        else:
            raise Exception('Unrecognize frame type %04X' % self.data_type)
