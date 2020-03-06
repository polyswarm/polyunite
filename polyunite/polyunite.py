from itertools import chain
import re
from typing import Dict, Optional

from polyunite.utils import GROUP_COLORS, MAEC_ATTRIBUTE, reset
from polyunite.vocab import (
    ARCHIVES,
    HEURISTICS,
    IDENT,
    LABELS,
    LANGS,
    MACROS,
    OBFUSCATIONS,
    OSES,
    PLATFORM,
)

engines = {}


class EnginePattern:
    match: re.Match
    values: Dict[str, str]
    pattern: re.Pattern

    @classmethod
    def __init_subclass__(cls):
        if not isinstance(cls.pattern, re.Pattern):
            cls.pattern = re.compile(cls.pattern, re.VERBOSE)
        engines[cls.__name__.lower()] = cls

    def __init__(self, classification: str):
        self.match = self.pattern.fullmatch(classification)
        self.values = {k: v for k, v in self.match.groupdict().items() if v}

    def colorize(self) -> str:
        """Colorize a classification string"""
        ss = self.classification_name
        # interleave the color, match & reset between the part before & after the match (from rpartition)
        for name, match in filter(lambda kv: kv[0] in GROUP_COLORS, self.values.items()):
            ss = ''.join(chain(*zip(ss.rpartition(match), (GROUP_COLORS[name], reset, ''))))
        return ss

    def first(self, keys):
        return filter(None, map(self.values.get, keys))

    @property
    def heuristic(self) -> Optional[bool]:
        matches = self.first(('HEURISTICS', 'FAMILY', 'LABELS', 'VARIANT'))
        return any(map(HEURISTICS.compile(1, 1).fullmatch, matches))

    @property
    def peripheral(self) -> bool:
        return not self.labels.isdisjoint({
            'test', 'nonmalware', 'greyware', 'shellcode', 'security_assessment_tool', 'parental_control', 'web_bug'
        })

    @property
    def name(self) -> str:
        try:
            pairs = zip(
                self.first(('FAMILY', 'LANGS', 'MACROS', 'OPERATING_SYSTEMS', 'LABELS')),
                self.first(('VARIANT', 'SUFFIX'))
            )
            return '.'.join(next(pairs))
        except StopIteration:
            return self.classification_name

    @MAEC_ATTRIBUTE
    def classification_name(self) -> Optional[str]:
        return self.match and self.match.string

    av_vendor = MAEC_ATTRIBUTE(lambda self: self.__class__.__name__)
    operating_system = MAEC_ATTRIBUTE(OSES)
    language = MAEC_ATTRIBUTE(LANGS)
    macro = MAEC_ATTRIBUTE(MACROS)
    labels = MAEC_ATTRIBUTE(LABELS, reciever=set)


class Alibaba(EnginePattern):
    pattern = rf"^(?:(?:{OBFUSCATIONS}|{LABELS:x}):)?(?:({PLATFORM})\/)?(?:{IDENT})$"


class ClamAV(EnginePattern):
    pattern = rf"""^
        (?:(?P<PREFIX>BC|Clamav))?
        (?:(\.|^)(?:{PLATFORM}|{LABELS}|{OBFUSCATIONS}))*?

        (?:(\.|^)(?P<FAMILY>\w+)(?:(\:\w|\/\w+))*(?:-(?P<VARIANT>[\-0-9]+)))?$"""


class DrWeb(EnginePattern):
    pattern = rf"""^
    ((?i:{HEURISTICS})(\s+(of\s*)?)?)?
              (?:(\.|\A|\b){PLATFORM})?
              (?:(\.|\A|\b){LABELS})?
              (?:(\.|\b)( # MulDrop6.38732 can appear alone or in front of another `.`
                  (?P<FAMILY>[A-Za-z][-\w\.]+?)
                  (?:\.|\Z) # and either end or continue with `.`
                  (?P<VARIANT>[0-9]+)?
                  (?:[.]?(?P<SUFFIX>(origin|based)))?))?$"""


class Ikarus(EnginePattern):
    pattern = rf"""
        ^({OBFUSCATIONS}\.)?
              (?:{HEURISTICS}\:?)?
              (?:(?:\A|\.|\b)({LABELS:x}|{PLATFORM}))*?
              (?:[.]?{IDENT})?$"""


class Jiangmin(EnginePattern):
    pattern = rf"""^(?:{HEURISTICS}:?)?
              (?:(?:{LABELS:x}|{OBFUSCATIONS}|{PLATFORM})[./]|\b)+?
              {IDENT}?(?:[.](?P<GENERATION>[a-z]))?$"""


class K7(EnginePattern):
    pattern = rf"^{LABELS:x}? (?:\s*\(\s* (?P<VARIANT>[a-f0-9]+) \s*\))?$"


class Lionic(EnginePattern):
    pattern = rf"^{LABELS}?(?:(^|\.)(?:{PLATFORM}))?(?:(?:\.|^){IDENT})?$"


class NanoAV(EnginePattern):
    pattern = rf"""^
        {LABELS:x}?
              (?:[.]?(?P<NANO_TYPE>(Text|Url)))?
              (?:(\b|[.]){PLATFORM})*?
              (?:[.]?{IDENT})$"""


class Qihoo360(EnginePattern):
    pattern = rf"""
        ^(?:{HEURISTICS}(?:/|(?:(?<=VirusOrg)\.)))?
              (?:
                  (?:Application|{MACROS}|{LANGS}|{OSES}|{ARCHIVES}|{LABELS:x}|(QVM\d*(\.\d)?(\.[0-9A-F]+)?))
              [./])*
              {IDENT}?$"""


class QuickHeal(EnginePattern):
    pattern = rf"""
        ^(?:{HEURISTICS}\.)?
              # This trailing (\)$) handle wierd cases like 'Adware)' or 'PUP)'
              (?:(?:\.|^)?{LABELS:x}(\)\Z)?)?
              (?:(?:\.|^){PLATFORM})?
              (?:(?:\.|\/|^)
                  (?:(?P<FAMILY>[-\w]+))
                  (?:\.(?P<VARIANT>\w+))?
                  (?:\.(?P<SUFFIX>\w+))?)?$"""


class Rising(EnginePattern):
    pattern = rf"""^
            {LABELS:x}?
            (?:
                (?:(?:^|\/|\.){PLATFORM}) |
                (?:(?:\.|\/)(?P<FAMILY>[iA-Z][\-\w]+))
            )*
            (?:(?P<VARIANT>(?:[#@!.][a-zA-Z0-9]+)*?)%?)?$"""

    @property
    def name(self) -> str:
        keys = tuple(map(self.values.get, ('FAMILY', 'VARIANT')))
        return ''.join((keys if all(keys) else self.classification_name))


class Virusdie(EnginePattern):
    pattern = rf"""^
        (?:{HEURISTICS})?
        (?:(?:\A|\b|\.)(?:{LANGS}|{LABELS}))*
        (?:(?:\A|\b|\.){IDENT})?
    $"""
