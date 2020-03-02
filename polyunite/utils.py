from collections import UserDict
import re
from string import ascii_lowercase, ascii_uppercase, whitespace


def trx(ss: str):
    return (ss or '').translate(str.maketrans(ascii_uppercase, ascii_lowercase, whitespace))


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
    'LABELS': yellow,
    'ARCHIVES': black,
    'HEURISTICS': underline,
    'MACROS': green,
    'LANGS': blue,
    'OPERATING_SYSTEMS': cyan,
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


Schemes = EngineSchemes()


def parse(name, classification: str):
    return name in Schemes and Schemes[name](classification)


def MAEC_ATTRIBUTE(src, every=False, container=set):
    span = getattr(src, 'name', src)

    if callable(span):
        fn = span
    elif every:

        def fetch_all(self):
            group = self.values.get(span, r'\Z\A')
            return container(filter(None, (m.lastgroup for m in pattern.finditer(group))))

        pattern = src.compile(1)
        fn = fetch_all
    else:

        def driver(self):
            match = self.values.get(span)
            if match:
                gen = (k for k, v in self.values.items() if v == match and k != span)
                return next(gen, None)

        fn = driver

    return property(fn)
