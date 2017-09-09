import colored


def b2mac(x):
    return ':'.join(['%02X' % i for i in x])

def b2ip(x):
    return '.'.join(map(str, x))

class btable(object):
    def __init__(self, x):
        self.data = {}
        for k, v in x.items():
            self.data[k] = v
            self.data[v] = k
    
    def __getitem__(self, k):
        return self.data[k]

    def __contains__(self, k):
        return k in self.data


def color(x, bg):
    return colored.fg(bg) + str(x) + colored.attr('reset')
