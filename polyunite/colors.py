from enum import Enum


class color(Enum):
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

    @staticmethod
    def at(ss: str, color: 'color'):
        return color.value + ss + color.RESET.value
