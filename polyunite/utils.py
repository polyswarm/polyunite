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
antecedent = format_template(r'{0}?(?<={0})')


def colorized_report():
    def print_heading(msg):
        print("{:-^150}".format(msg))

    try:
        it = match_iter()
        while True:
            print(format_match(*next(it)))
    except StopIteration as e:
        missing, errors = e.value

    print_heading("FAILURES")
    for engine, label, err in errors:
        print("{:<15}: {:85} : {}".format(engine, label, err))

    print_heading("INFO")
    print('compile.cache_info: ', polyunite.vocab.VocabRegex.compile.cache_info())

    print_heading("MISSING")
    print(missing)
