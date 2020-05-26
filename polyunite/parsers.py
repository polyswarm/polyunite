import collections
from contextlib import suppress
from typing import ClassVar, Dict

import regex as re

from polyunite.errors import MatchError
from polyunite.utils import colors
from polyunite.vocab import VocabRegex, group

from .registry import registry

# regular expressions which match 'vocabularies' of classification components
LABELS = VocabRegex.from_resource('LABELS')
LANGS = VocabRegex.from_resource('LANGS')
ARCHIVES = VocabRegex.from_resource('ARCHIVES')
MACROS = VocabRegex.from_resource('MACROS')
OSES = VocabRegex.from_resource('OPERATING_SYSTEMS')
HEURISTICS = VocabRegex.from_resource('HEURISTICS')
OBFUSCATIONS = VocabRegex.from_resource('OBFUSCATIONS')
SUFFIXES = VocabRegex.from_resource('SUFFIXES')
PLATFORM = group(OSES, ARCHIVES, MACROS, LANGS)
IDENT = r"""(?P<NAME>(?P<FAMILY>(?P<CVE>(?:CVE-[\d-]+))|BO|(?:[0-9]?[A-Z][\w_-]{2,}))?
                ([.](?P<VARIANT>(?:[a-zA-Z0-9]*)([.]\d+\Z)?))?
                ((?P<SUFFIX>(!\w+|[.]origin|[.][a-z]+)))?)"""


def extract_vocabulary(vocab, recieve=lambda m: next(m, None)):
    sublabels = vocab.sublabels
    return lambda self: recieve(label for label in sublabels if label in self)


class Classification(collections.UserDict):
    pattern: 'ClassVar[str]'
    regex: 'ClassVar[re.Pattern]'
    data: 'Dict[str, str]'

    def __init__(self, name: str):
        super().__init__()
        try:
            self.match = self.regex.fullmatch(name)
            self.data = {k: v for k, v in self.match.groupdict().items() if v}
        except (AttributeError, TypeError):
            raise MatchError(name)

    operating_system = property(extract_vocabulary(OSES))
    language = property(extract_vocabulary(LANGS))
    macro = property(extract_vocabulary(MACROS))
    labels = property(extract_vocabulary(LABELS, recieve=set))

    @classmethod
    def __init_subclass__(cls):
        cls.regex = re.compile(cls.pattern, re.VERBOSE)
        registry.register(cls, cls.__name__)

    @classmethod
    def from_string(cls, name: 'str') -> 'Classification':
        """Build a `Classification` from the raw malware name provided by this engine"""
        return cls(name)

    @classmethod
    def guess_heuristic(cls, name: 'str') -> 'bool':
        try:
            return cls.from_string(name).is_heuristic
        except MatchError:
            return False

    @property
    def source(self):
        return self.match.string

    @property
    def name(self) -> str:
        """'name' of the virus"""
        return self.get('FAMILY', self.source)

    @property
    def av_vendor(self) -> str:
        """Engine / AV vendor's name"""
        return self.__class__.__name__

    @property
    def is_heuristic(self) -> bool:
        """Check if we've parsed this classification as a heuristic-detection"""
        fields = map(self.get, (HEURISTICS.name, LABELS.name, 'VARIANT', 'FAMILY'))
        return any(map(HEURISTICS.compile(1, 1).fullmatch, filter(None, fields)))

    def colorize(
        self,
        style={
            'NAME': colors.UNDERLINE,
            'LABELS': colors.YELLOW_FG,
            'ARCHIVES': colors.RED_FG,
            'HEURISTICS': colors.MAGENTA_FG,
            'MACROS': colors.UNDERLINE + colors.RED_FG,
            'LANGS': colors.BLUE_FG,
            'OPERATING_SYSTEMS': colors.CYAN_FG,
            'FAMILY': colors.GREEN_FG,
            'VARIANT': colors.WHITE_FG,
            'OBFUSCATIONS': colors.WHITE_FG + colors.UNDERLINE,
        }
    ) -> str:
        """Colorize a classification string"""
        markers = list(self.source)
        for name, style in style.items():
            with suppress(IndexError):
                for start, end in self.match.spans(name):
                    markers[start] = style + self.source[start]
                    markers[end] = colors.RESET + self.source[end]
        return ''.join(markers) + colors.RESET


class Alibaba(Classification):
    pattern = rf"^(?:(?:{OBFUSCATIONS}|{LABELS}*):)?(?:({PLATFORM})[./])*(?i:{IDENT})$"


class ClamAV(Classification):
    pattern = rf"""^
        (?:(?P<PREFIX>BC|Clamav))?
        (?:(\.|^)(?:{PLATFORM}|{LABELS}|{OBFUSCATIONS}))*?

        (?:(\.|^)(?P<FAMILY>\w+)(?:(\:\w|\/\w+))*(?:-(?P<VARIANT>[\-0-9]+)))?$"""


class DrWeb(Classification):
    pattern = rf"""^
    ((?i:{HEURISTICS})(\s+(of\s*)?)?)?
              (?:(\.|\A|\b){PLATFORM})?
              (?:(\.|\A|\b){LABELS})?
              (?:(\.|\b)( # MulDrop6.38732 can appear alone or in front of another `.`
                  (?P<FAMILY>[A-Za-z][-\w\.]+?)
                  (?:\.|\Z) # and either end or continue with `.`
                  (?P<VARIANT>[0-9]+)?
                  (?:[.]?(?P<SUFFIX>(origin|based)))?))?$"""


class Ikarus(Classification):
    pattern = rf"""^
              (?:{HEURISTICS}\:?)?
              (?:(?:\A|[.]|\b)(-?{LABELS}|{OBFUSCATIONS}|{PLATFORM}))*
              (?:(?:\A|[.]|\b){IDENT})?$"""


class Jiangmin(Classification):
    pattern = rf"""^(?:{HEURISTICS}:?)?
              (?:(?:({LABELS}+)|{OBFUSCATIONS}|{PLATFORM})[./]|\b)+
              {IDENT}?$"""


class K7(Classification):
    pattern = rf"^([-]?{LABELS})+ (?:\s*\(\s* (?P<VARIANT>[a-f0-9]+) \s*\))?$"


class Lionic(Classification):
    pattern = rf"^{LABELS}?(?:(^|\.)(?:{PLATFORM}))*(?:(?:\.|^){IDENT})?$"


class NanoAV(Classification):
    pattern = rf"""^
        (?:Marker[.])?
        (?:{LABELS}+)?
              (?:[.]?(?P<NANO_TYPE>(Text|Url)))?
              (?:(^|[.]){PLATFORM})*
              (?:([.]|^){IDENT})$"""


class Qihoo360(Classification):
    pattern = rf"""
        ^(?:{HEURISTICS}(?:/|(?:(?<=VirusOrg)\.)))?
              (?:(?:Application|({PLATFORM})|{LABELS}|(QVM\d*(\.\d)?(\.[0-9A-F]+)?))([.]|\/|\Z))*
              (?i:{IDENT})?$"""


class QuickHeal(Classification):
    pattern = rf"""
        ^(?:{HEURISTICS}\.)?
              (?:(?:{LABELS})+)?
              # This trailing (\)$) handle wierd cases like 'Adware)' or 'PUP)'
              (?:(\)$))?
              (?:(?:\.|^){PLATFORM})?
              (?:(?:\.|\/|^)
                  (?:(?P<FAMILY>[-\w]+))
                  (?:\.(?P<VARIANT>\w+))?
                  (?:\.(?P<SUFFIX>\w+))?)?$"""


class Rising(Classification):
    pattern = rf"""^
            ([.]?{LABELS})*
            (?:
                (?:(?:^|\/|\.){PLATFORM}) |
                (?:(?:\.|\/)(?P<FAMILY>(?P<CVE>CVE-\d{4}-\d+)|[iA-Z][\-\w]+?))
            )*
            (?:(?P<VARIANT>(?:[#@!.][a-zA-Z0-9]+)*?)%?)?$"""


class Virusdie(Classification):
    pattern = rf"""^
        (?:{HEURISTICS})?
        (?:(?:\A|\b|\.)(?:{LANGS}|{LABELS}))*
        (?:(?:\A|\b|\.){IDENT})?
    $"""


class URLHaus(Classification):
    pattern = rf"""^
        (({LABELS})(\.|$))?
        (?P<FAMILY>[\s\w]+)?
    $"""
