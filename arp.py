import struct
from utils import b2ip, b2mac


def ARP(x, log):
    h_type, p_type, h_len, p_len = struct.unpack('>HHBB', x[:6])
    assert h_type == 1 and h_len == 6, 'Invalid hardware type'
    assert p_type == 0x0800 and p_len == 4, 'Invalid protocol type'

    op, = struct.unpack('>H', x[6:8])
    if op == 1:
        pass # arp request
    elif op == 2:
        pass # arp response
    elif op == 3:
        pass # rarp request
    elif op == 4:
        pass # rarp response
    else:
        raise Exception('Invalid arp operation: %04X' % op)

    src_mac = struct.unpack('6B', x[8:14])
    src_ip = struct.unpack('4B', x[14:18])
    dst_mac = struct.unpack('6B', x[18:24])
    dst_ip = struct.unpack('4B', x[24:28])
    path = (
        '%s %s' % (b2mac(src_mac), b2ip(src_ip)),
        '%s %s' % (b2mac(dst_mac), b2ip(dst_ip)),
    )
    log('arp', path, '%04X %04X' % (h_type, p_type))
    exit()
