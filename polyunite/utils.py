import string

DELNONALPHA = str.maketrans(
    string.ascii_uppercase, string.ascii_lowercase, string.punctuation + string.whitespace
)


def trx(ss: str):
    return ss.translate(DELNONALPHA)
