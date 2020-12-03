from typing import Optional


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
    return spec.format('|'.join(set(map(format, filter(None, choices)))))


class format_template(str):
    """A template string parameterized by it's format specification directly"""
    __format__ = str.format


# consume `{0}` if matches *AND* ensures this match is preceeded by `{0}`.
# This may seem redundant but is useful in regular expressions where the
# prior match may have already consumed by another regular expression.
antecedent = format_template(r'({0}?(?<={0}))')


def edit_distance(x: str, y: str) -> float:
    """
    Levenshtein distance between `x` & `y`

    .. seealso::

        `<https://en.wikipedia.org/wiki/Levenshtein_distance#Iterative_with_two_matrix_rows>`_
            Psuedocode & description of this implementation
    """
    if not isinstance(x, str) or not isinstance(y, str):
        raise TypeError("Invalid arguments: type(x)=%s, type(y)=%s" % type(x), type(y))

    if x == y:
        return 0.0

    if len(x) == 0:
        return len(y)

    if len(y) == 0:
        return len(x)

    v0 = list(range(0, len(y) + 1))
    v1 = [0] * len(v0)

    for i in range(len(x)):
        v1[0] = i + 1
        for j in range(len(y)):
            cost = 0 if x[i] == y[j] else 1
            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
        v0, v1 = v1, v0

    return v0[len(y)]
