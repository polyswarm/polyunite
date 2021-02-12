from typing import Optional

from collections.abc import Iterable


class colors:
    BLACK_FG = '\033[30m'
    RED_FG = '\033[31m'
    GREEN_FG = '\033[32m'
    YELLOW_FG = '\033[33m'
    BLUE_FG = '\033[34m'
    MAGENTA_FG = '\033[35m'
    CYAN_FG = '\033[36m'
    WHITE_FG = '\033[37m'
    ORANGE_FG = '\033[91m'
    PINK_FG = '\033[95m'
    RESET = '\033[0m'
    UNDERLINE = '\033[4m'


def group(*choices, fmt='(?:{})', name: 'Optional[str]' = None):
    """Group a regular expression"""
    spec = '(?P<%s>{})' % name if name else fmt
    return spec.format('|'.join(map(format, filter(None, choices))))


def flatmap(fn, seqs):
    """ Apply ``fn`` to each elt of ``seqs``, concatenating results."""
    for elt in map(fn, seqs):
        if isinstance(elt, Iterable) and not isinstance(elt, str):
            yield from elt
        else:
            yield elt
