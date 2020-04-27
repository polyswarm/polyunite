import collections
from functools import partial
from itertools import chain
import re
from typing import ClassVar, Dict, Optional

from polyunite.utils import GROUP_COLORS, reset
from polyunite.registry import registry
from polyunite.colors import GROUP_COLORS, RESET
from polyunite.vocab import ARCHIVES, HEURISTICS, IDENT, LABELS, LANGS, MACROS, OBFUSCATIONS, OSES, PLATFORM


class ClassificationDecoder(collections.UserDict):
    pattern: 'ClassVar[str]'
    regex: 'ClassVar[re.Pattern]'

    operating_system = property(OSES.find_with)
    language = property(LANGS.find_with)
    macro = property(MACROS.find_with)
    labels = property(partial(LABELS.find_with, reciever=set))

    @property
    def classification_name(self):
        return self.match.string

    @property
    def av_vendor(self):
        return self.__class__.__name__

    @classmethod
    def __init_subclass__(cls):
        if not isinstance(cls.pattern, re.Pattern):
            cls.regex = re.compile(cls.pattern, re.VERBOSE)
        registry.map_to_decoder(cls.__name__, cls)

    def __init__(self, classification: str):
        match = self.regex.fullmatch(classification)
        if not match:
            raise ValueError
        self.match = match
        self.data = {k: v for k, v in match.groupdict().items() if v}

    def colorize(self) -> str:
        """Colorize a classification string"""
        ss = self.classification_name
        # interleave the color, match & reset between the part before & after the match (from rpartition)
        for name, match in filter(lambda kv: kv[0] in GROUP_COLORS, self.items()):
            ss = ''.join(chain(*zip(ss.rpartition(match), (GROUP_COLORS[name], RESET, ''))))
        return ss

    @property
    def is_heuristic(self) -> Optional[bool]:
        match = HEURISTICS.compile(1, 1).fullmatch
        for field in ('HEURISTICS', 'FAMILY', 'LABELS', 'VARIANT'):
            if field in self and match(self[field]):
                return True

    @property
    def is_paramalware(self) -> bool:
        return not self.labels.isdisjoint({
            'test',
            'nonmalware',
            'greyware',
            'shellcode',
            'security_assessment_tool',
            'parental_control',
            'web_bug',
        })

    @property
    def name(self) -> str:
        return self.get('FAMILY') or self.classification_name


class Alibaba(ClassificationDecoder):
    pattern = rf"^(?:(?:{OBFUSCATIONS}|{LABELS:x}):)?(?:({PLATFORM})\/)?(?:{IDENT})$"


class ClamAV(ClassificationDecoder):
    pattern = rf"""^
        (?:(?P<PREFIX>BC|Clamav))?
        (?:(\.|^)(?:{PLATFORM}|{LABELS}|{OBFUSCATIONS}))*?

        (?:(\.|^)(?P<FAMILY>\w+)(?:(\:\w|\/\w+))*(?:-(?P<VARIANT>[\-0-9]+)))?$"""


class DrWeb(ClassificationDecoder):
    pattern = rf"""^
    ((?i:{HEURISTICS})(\s+(of\s*)?)?)?
              (?:(\.|\A|\b){PLATFORM})?
              (?:(\.|\A|\b){LABELS})?
              (?:(\.|\b)( # MulDrop6.38732 can appear alone or in front of another `.`
                  (?P<FAMILY>[A-Za-z][-\w\.]+?)
                  (?:\.|\Z) # and either end or continue with `.`
                  (?P<VARIANT>[0-9]+)?
                  (?:[.]?(?P<SUFFIX>(origin|based)))?))?$"""


class Ikarus(ClassificationDecoder):
    pattern = rf"""
        ^({OBFUSCATIONS}\.)?
              (?:{HEURISTICS}\:?)?
              (?:(?:\A|\.|\b)({LABELS:x}|{PLATFORM}))*?
              (?:[.]?{IDENT})?$"""


class Jiangmin(ClassificationDecoder):
    pattern = rf"""^(?:{HEURISTICS}:?)?
              (?:(?:{LABELS:x}|{OBFUSCATIONS}|{PLATFORM})[./]|\b)+?
              {IDENT}?(?:[.](?P<GENERATION>[a-z]))?$"""


class K7(ClassificationDecoder):
    pattern = rf"^{LABELS:x}? (?:\s*\(\s* (?P<VARIANT>[a-f0-9]+) \s*\))?$"


class Lionic(ClassificationDecoder):
    pattern = rf"^{LABELS}?(?:(^|\.)(?:{PLATFORM}))?(?:(?:\.|^){IDENT})?$"


class NanoAV(ClassificationDecoder):
    pattern = rf"""^
        {LABELS:x}?
              (?:[.]?(?P<NANO_TYPE>(Text|Url)))?
              (?:(\b|[.]){PLATFORM})*?
              (?:[.]?{IDENT})$"""


class Qihoo360(ClassificationDecoder):
    pattern = rf"""
        ^(?:{HEURISTICS}(?:/|(?:(?<=VirusOrg)\.)))?
              (?:
                  (?:Application|{MACROS}|{LANGS}|{OSES}|{ARCHIVES}|{LABELS:x}|(QVM\d*(\.\d)?(\.[0-9A-F]+)?))
              [./])*
              {IDENT}?$"""


class QuickHeal(ClassificationDecoder):
    pattern = rf"""
        ^(?:{HEURISTICS}\.)?
              # This trailing (\)$) handle wierd cases like 'Adware)' or 'PUP)'
              (?:(?:\.|^)?{LABELS:x}(\)\Z)?)?
              (?:(?:\.|^){PLATFORM})?
              (?:(?:\.|\/|^)
                  (?:(?P<FAMILY>[-\w]+))
                  (?:\.(?P<VARIANT>\w+))?
                  (?:\.(?P<SUFFIX>\w+))?)?$"""


class Rising(ClassificationDecoder):
    pattern = rf"""^
            {LABELS:x}?
            (?:
                (?:(?:^|\/|\.){PLATFORM}) |
                (?:(?:\.|\/)(?P<FAMILY>[iA-Z][\-\w]+))
            )*
            (?:(?P<VARIANT>(?:[#@!.][a-zA-Z0-9]+)*?)%?)?$"""

    @property
    def name(self) -> str:
        keys = tuple(map(self.get, ('FAMILY', 'VARIANT')))
        return ''.join((keys if all(keys) else self.classification_name))


class Virusdie(ClassificationDecoder):
    pattern = rf"""^
        (?:{HEURISTICS})?
        (?:(?:\A|\b|\.)(?:{LANGS}|{LABELS}))*
        (?:(?:\A|\b|\.){IDENT})?
    $"""


class URLHaus(ClassificationDecoder):
    pattern = rf"""^
        (({LABELS})(\.)?)?
        (?P<FAMILY>[\s\w]+)
    $"""
