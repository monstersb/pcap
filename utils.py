def b2mac(x):
    return ':'.join(['%02X' % i for i in x])

def b2ip(x):
    return '.'.join(map(str, x))

