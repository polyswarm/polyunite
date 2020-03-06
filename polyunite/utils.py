import operator

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


def MAEC_ATTRIBUTE(src, reciever=lambda matches: next(matches, None)):
    """IN THE FUTURE THIS FUNCTION WILL ATTACH MAEC INFOMATION TO PROPERTIES"""
    if hasattr(src, 'name'):
        # the id/name of the regex group to search for submatches of
        gid = src.name
        # a function which returns an iterator of matches from `gid`
        find = src.compile(1, 1).finditer
        last = operator.attrgetter('lastgroup')
        return property(lambda self: reciever(filter(None, map(last, find(self.values.get(gid, ''))))))
    else:
        return property(src)
