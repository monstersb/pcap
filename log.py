#! /usr/bin/env python
# -*- coding: utf-8 -*-

import colored


def color(bg, x):
    return colored.fg(bg) + x + colored.attr('reset')

def log(deep, protocol, path, data):
    protocol = color('yellow', '[%s]' % protocol)
    path = '(%s -> %s)' % (color('cyan', path[0]), color('cyan', path[1])) if path else ''
    print('  ' * deep, protocol, path, data)

