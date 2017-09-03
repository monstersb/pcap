import struct


def mac(x):
    return ':'.join(['%02X' % i for i in x])

def ip(x):
    return '.'.join(map(str, x))

def Ethernet(src, log):
    assert len(src) >= 14, 'Invalid ethernet frame'
    src_mac = struct.unpack('6B', src[:6])
    dst_mac = struct.unpack('6B', src[6:12])
    data_type, = struct.unpack('>H', src[12:14])
    log('[ethernet] %04X %s -> %s' % (data_type, mac(src_mac), mac(dst_mac)))
    if data_type == 0x0800:
        IPPacket(src[14:], log)

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
    log('[ipv%d] Protocol:%02X TTL:%d %s -> %s' % (ver, proto, ttl, ip(src_ip), ip(dst_ip)))
