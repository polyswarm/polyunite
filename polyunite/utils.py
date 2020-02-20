import string

DELNONALPHA = str.maketrans(
    string.ascii_uppercase, string.ascii_lowercase, string.punctuation + string.whitespace
)


def trx(ss: str):
    return ss.translate(DELNONALPHA)


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
    'NAME': red,
    'PLATFORM': magenta + underline,
    'LABEL': yellow,
    'VENDORID': blue,
    'PREFIX': cyan,
    'CONFIDENCE': underline,
    'FAMILY': red,
    'VARIANT': green,
    'OBFUSCATION': black,
    'EXTRA': white,
    'EXPLOIT': white,
    'DDOS': white,
    'BEHAVIOR': white
}
