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


def MAEC_ATTRIBUTE(src, every=False, container=set):
    def driver(self):
        try:
            return wrapper(filter(None, map(lambda m: m.lastgroup, match(self.values.get(span, r'')))))
        except StopIteration:
            return None

    if callable(src):
        return property(src)

    span = src.name
    pattern = src.compile(1)
    match = pattern.finditer
    wrapper = container if every else next
    return property(driver)
