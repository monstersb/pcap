import struct


class Pcap(object):

    def __init__(self, stream):
        self._stream = stream
        self._header = stream.read(0x18)
        assert len(self._header) == 0x18, 'Invalid pcap file'

        self.magic, self.ver_maj, self.ver_min, self.this_zone, self.sigfigs, self.snaplen, self.link_type = struct.unpack('IHHIIII', self._header)

        assert self.magic == 0xA1B2C3D4, 'Invalid pcap file'

        #self._log('pcap major version: %d' % self.ver_maj)
        assert self.ver_maj == 2, 'Invalid pcap version'

        #self._log('pcap minor version: %d' % self.ver_min)
        assert self.ver_min == 4, 'Invalid pcap version'

        #self._log('pcap snap len: %d' % self.snaplen)
        #self._log('pcap link type: %d' % self.link_type)

    def read(self):
        header = self._stream.read(0x10)
        assert len(header) == 0x10, 'Incomplete pcap packet'

        sec, msec, cap_len, real_len = struct.unpack('IIII', header)
        #self._log(0, 'pcap', None, '%04X %d.%d' % (self.link_type, sec, msec))
        
        data = self._stream.read(cap_len)
        return sec, msec, real_len, data
