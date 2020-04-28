import operator
from typing import Optional


class colors:
    BLACK_FG = '0\033[30m'
    BLUE_FG = '\033[34m'
    CYAN_FG = '\033[36m'
    GREEN_FG = '\033[32m'
    MAGENTA_FG = '\033[35m'
    RED_FG = '\033[31m'
    WHITE_FG = '\033[37m'
    YELLOW_FG = '\033[33m'
    RESET = '\033[0m'
    UNDERLINE = '\033[4m'


def group(*choices, fmt='(?:{})', name: 'Optional[str]' = None):
    """Group a regular expression"""
    spec = '(?P<%s>{})' % name if name else fmt
    return spec.format('|'.join(set(map(format, filter(None, choices)))))


def extract_vocabulary(vocab, recieve=lambda m: next(m, None)):
    """Build a function which extracts a vocabulary match"""
    name = vocab.name
    find_iter = vocab.compile(1, 1).finditer
    last_group = operator.attrgetter('lastgroup')

    def driver(self):
        try:
            return recieve(filter(None, map(last_group, find_iter(self[name]))))
        except KeyError:
            return recieve(iter(()))

    return driver
