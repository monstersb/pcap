import struct
from ip import IPPacket
from arp import ARP
from utils import b2mac


frame_type = {
    0x0800: 'IP',
    0x0806: 'ARP',
}

def Ethernet(src, log):
    assert len(src) >= 14, 'Invalid ethernet frame'
    src_mac = struct.unpack('6B', src[:6])
    dst_mac = struct.unpack('6B', src[6:12])
    data_type, = struct.unpack('>H', src[12:14])
    log('ethernet', (b2mac(src_mac), b2mac(dst_mac)), '%04X' % (data_type))
    if data_type == 0x0800:
        IPPacket(src[14:], log)
    elif data_type == 0x0806:
        ARP(src[14:], log)
