import struct
from utils import b2ip


def IPPacket(src, log):
    src_ip = struct.unpack('4B', src[12:16])
    dst_ip = struct.unpack('4B', src[16:20])
    t, tos, length = struct.unpack('>BBH', src[:4])
    ver = (t & 0b11110000) >> 4
    header_length = ((t & 0b1111) >> 4) * 4
    ser, offset = struct.unpack('>HH', src[4:8])
    flag = offset & 0b111
    offset = offset >> 3
    ttl, proto, crc = struct.unpack('>BBH', src[8:12])
    log('ipv%d' % ver, (b2ip(src_ip), b2ip(dst_ip)), 'Protocol:%02X TTL:%d' % (proto, ttl))
