import collections
from itertools import chain
import re
from typing import ClassVar, Dict

from polyunite.errors import MatchError
from polyunite.utils import colors, extract_vocabulary, group
from polyunite.vocab import VocabRegex

from .registry import EngineRegistry

# regular expressions which match 'vocabularies' of classification components
LABELS = VocabRegex.from_resource('LABELS')
LANGS = VocabRegex.from_resource('LANGS')
ARCHIVES = VocabRegex.from_resource('ARCHIVES')
MACROS = VocabRegex.from_resource('MACROS')
OSES = VocabRegex.from_resource('OPERATING_SYSTEMS')
HEURISTICS = VocabRegex.from_resource('HEURISTICS')
OBFUSCATIONS = VocabRegex.from_resource('OBFUSCATIONS')
PLATFORM = group(OSES, ARCHIVES, MACROS, LANGS)
IDENT = r"""(?P<NAME> (?P<FAMILY>(?:CVE-[\d-]+)|(?:[\w_-]+))
                ([.]?(?<=[.])(?P<VARIANT>(?:[a-zA-Z0-9]*)([.]\d+\Z)?))?
                (!(?P<SUFFIX>\w+))?)"""


class ClassificationParser(collections.UserDict):
    pattern: 'ClassVar[str]'
    regex: 'ClassVar[re.Pattern]'
    data: 'Dict[str, str]'
    source: 'str'

    @classmethod
    def __init_subclass__(cls):
        cls.regex = re.compile(cls.pattern, re.VERBOSE)
        EngineRegistry.create_parser(cls, cls.__name__)

    def __init__(self, classification: str):
        super().__init__()
        self.source = classification
        match = self.regex.fullmatch(classification)
        if match:
            self.data = {k: v for k, v in match.groupdict().items() if v}
        if not self.data:
            raise MatchError

    operating_system = property(extract_vocabulary(OSES))
    language = property(extract_vocabulary(LANGS))
    macro = property(extract_vocabulary(MACROS))
    labels = property(extract_vocabulary(LABELS, recieve=set))

    @property
    def name(self) -> str:
        """'name' of the virus"""
        # for those really hard to parse lables
        pattern = rf"""^({LABELS:x})?
                        ({LANGS:x})?
                        ({ARCHIVES:x})?
                        ({MACROS:x})?
                        ({OSES:x})?
                        ({OBFUSCATIONS:x})?
                        ({HEURISTICS:x})?
                       $"""
        regex = re.compile(pattern, re.VERBOSE)
        match = regex.fullmatch(self.get('FAMILY', ''))
        if match:
            return ''
        return self.get('FAMILY', self.source)

    @property
    def av_vendor(self) -> str:
        """Engine / AV vendor's name"""
        return self.__class__.__name__

    @property
    def is_heuristic(self) -> bool:
        """Check if we've parsed this classification as a heuristic-detection"""
        fields = map(self.get, ('HEURISTICS', 'FAMILY', 'LABELS', 'VARIANT'))
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
            'OBFUSCATION': colors.BLACK_FG,
        }
    ) -> str:
        """Colorize a classification string"""
        ss = self.source
        # interleave the colors, match & reset between the part before & after the match (from rpartition)
        for name, match in filter(lambda kv: kv[0] in style, self.items()):
            ss = ''.join(chain(*zip(ss.rpartition(match), (style[name], colors.RESET, ''))))
        return ss


class Alibaba(ClassificationParser):
    pattern = rf"""^(?:(?:{OBFUSCATIONS}|{LABELS:x}):)?
                    (?:({PLATFORM})\/)?
                    (?:{IDENT})$"""


class ClamAV(ClassificationParser):
    pattern = rf"""^
        (?:(?P<PREFIX>BC|Clamav))?
        (?:(\.|^)(?:{PLATFORM}|{LABELS}|{OBFUSCATIONS}))*?

        (?:(\.|^)(?P<FAMILY>\w+)(?:(\:\w|\/\w+))*(?:-(?P<VARIANT>[\-0-9]+)))?$"""


class DrWeb(ClassificationParser):
    pattern = rf"""^
    ((?i:{HEURISTICS})(\s+(of\s*)?)?)?
              (?:(\.|\A|\b){PLATFORM})?
              (?:(\.|\A|\b){LABELS})?
              (?:(\.|\b)( # MulDrop6.38732 can appear alone or in front of another `.`
                  (?P<FAMILY>[A-Za-z][-\w\.]+?)
                  (?:\.|\Z) # and either end or continue with `.`
                  (?P<VARIANT>[0-9]+)?
                  (?:[.]?(?P<SUFFIX>(origin|based)))?))?$"""


class Ikarus(ClassificationParser):
    pattern = rf"""^(not-a-virus:)? ({OBFUSCATIONS}\.)?
                    (({LABELS}(-\w+)?)\.)? (({PLATFORM})\.)? (?P<FAMILY>.*)?
                    $"""


class Jiangmin(ClassificationParser):
    pattern = rf"""^(?:{HEURISTICS}:?)?
              (?:(?:{LABELS:x}|{OBFUSCATIONS}|{PLATFORM})[./]|\b)+?
              {IDENT}?(?:[.](?P<GENERATION>[a-z]))?$"""


class K7(ClassificationParser):
    pattern = rf"""^{LABELS:x}?
                    (?:\s*\(\s* (?P<VARIANT>[a-f0-9]+) \s*\))?$"""

    @property
    def name(self) -> str:
        # K7 does not work with family names
        return ''


class Lionic(ClassificationParser):
    pattern = rf"""^{LABELS}?
                    (?:(^|\.)(?:{PLATFORM}))?
                    (?:(?:\.|^){IDENT})?$"""


class NanoAV(ClassificationParser):
    pattern = rf"""^
        {LABELS:x}?
              (?:[.]?(?P<NANO_TYPE>(Text|Url)))?
              (?:(\b|[.]){PLATFORM})*?
              (?:[.]?{IDENT})$"""


class Qihoo360(ClassificationParser):
    pattern = rf"""
        ^(?:{HEURISTICS}(?:/|(?:(?<=VirusOrg)\.)))?
              (?:
                  (?:Application|{MACROS}|{LANGS}|{OSES}|{ARCHIVES}|{LABELS:x}|(QVM\d*(\.\d)?(\.[0-9A-F]+)?))
              [./])*
              {IDENT}?$"""


class QuickHeal(ClassificationParser):
    pattern = rf"""
        ^(?:{HEURISTICS}\.)?
              # This trailing (\)$) handle wierd cases like 'Adware)' or 'PUP)'
              (?:(?:\.|^)?{LABELS:x}(\)\Z)?)?
              (?:(?:\.|^){PLATFORM})?
              (?:(?:\.|\/|^)
                  (?:(?P<FAMILY>[-\w]+))
                  (?:\.(?P<VARIANT>\w+))?
                  (?:\.(?P<SUFFIX>\w+))?)?$"""


class Rising(ClassificationParser):
    pattern = rf"""^
            {LABELS:x}?
            (?:
                (?:(?:^|\/|\.){PLATFORM}) |
                (?:(?:\.|\/)(?P<FAMILY>[iA-Z][\-\w]+))
            )*
            (?:(?P<VARIANT>(?:[#@!.][a-zA-Z0-9]+)*?)%?)?$"""


class Virusdie(ClassificationParser):
    pattern = rf"""^
        (?:{HEURISTICS})?
        (?:(?:\A|\b|\.)(?:{LANGS}|{LABELS}))*
        (?:(?:\A|\b|\.){IDENT})?
    $"""


class URLHaus(ClassificationParser):
    pattern = rf"""^
        (({LABELS})(\.|$))?
        (?P<FAMILY>[\s\w]+)?
    $"""
