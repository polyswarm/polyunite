from collections import UserDict
import string

DELNONALPHA = str.maketrans(string.ascii_uppercase, string.ascii_lowercase, string.whitespace)


def trx(ss: str):
    return (ss or '').translate(DELNONALPHA)


black = '\033[30m'
red = '\033[31m'
green = '\033[32m'
yellow = '\033[33m'
blue = '\033[34m'
magenta = '\033[35m'
cyan = '\033[36m'
white = '\033[37m'
underline = '\033[4m'
reset = '\033[0m'

GROUP_COLORS = {
    'NAME': underline,
    'PLATFORM': cyan,
    'LABEL': yellow,
    'PREFIX': cyan,
    'HEURISTIC': underline,
    'FAMILY': green,
    'VARIANT': white,
    'OBFUSCATION': black,
}


class EngineSchemes(UserDict):
    """A fancy dictionary for holding each engine, with easy lookup"""
    def __setitem__(self, k, v):
        return super().__setitem__(trx(k), v)

    def __getitem__(self, k):
        return super().__getitem__(trx(k))

    def __contains__(self, k):
        return super().__contains__(trx(k))

    def parse(self, name, classification: str):
        if name in self:
            return self[name](classification)
        return None
