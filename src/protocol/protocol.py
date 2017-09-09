import struct


class Protocol(object):
    def __init__(self, parrent, data):
        self._pos = 0
        self.parrent = parrent
        self.child = []
        self._data = data

    def parse(self):
        raise NotImplementedError()
    
    @property
    def deep(self):
        if self.parrent is None:
            return 0
        else:
            return self.parrent.deep + 1

    def _read(self, fmt):
        length = struct.calcsize(fmt)
        assert length <= len(self._data) - self._pos
        r = struct.unpack_from(fmt, self._data, self._pos)
        self._pos += length
        if len(r) == 1:
            return r[0]
        else:
            return r

    def __str__(self):
        return '[%s]' % (self.protocol)


    def verbose(self, deep=0):
        indent = '  ' * deep
        print(indent + str(self))
        for child in self.child:
            child.verbose(deep + 1)
