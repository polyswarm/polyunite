from itertools import chain
import re
from typing import Dict, Optional

from polyunite.utils import GROUP_COLORS, MAEC_ATTRIBUTE, Schemes, reset
from polyunite.vocab import (
    ARCHIVES,
    EXPLOITS,
    HEURISTICS,
    IDENT,
    LABELS,
    LANGS,
    MACROS,
    OBFUSCATIONS,
    OSES,
    PLATFORM,
)


class EnginePattern:
    match: re.Match
    values: Dict[str, str]
    pattern: re.Pattern

    @classmethod
    def __init_subclass__(cls):
        if not isinstance(cls.pattern, re.Pattern):
            cls.pattern = re.compile(cls.pattern, re.VERBOSE)
        Schemes[cls.__name__] = cls

    def __init__(self, classification: str):
        self.match = self.pattern.search(classification)
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
        return any(
            map(HEURISTICS.compile(1).search, self.first(('HEURISTICS', 'FAMILY', 'LABELS', 'VARIANT')))
        )

    @property
    def peripheral(self) -> bool:
        return not self.labels.isdisjoint({
            'test', 'nonmalware', 'greyware', 'shellcode', 'security_assessment_tool'
        })

    @property
    def name(self) -> str:
        try:
            return '.'.join(
                next(
                    zip(
                        self.first(('FAMILY', 'LANGS', 'MACROS', 'OPERATING_SYSTEMS', 'LABELS')),
                        self.first(('VARIANT', 'SUFFIX'))
                    )
                )
            )
        except StopIteration:
            return self.classification_name

    @MAEC_ATTRIBUTE
    def classification_name(self) -> Optional[str]:
        return self.match and self.match.string

    av_vendor = MAEC_ATTRIBUTE(lambda self: self.__class__.__name__)
    operating_system = MAEC_ATTRIBUTE(OSES)
    language = MAEC_ATTRIBUTE(LANGS)
    macro = MAEC_ATTRIBUTE(MACROS)
    labels = MAEC_ATTRIBUTE(LABELS, every=True, container=set)


class Alibaba(EnginePattern):
    pattern = rf"^(?:{LABELS}:)?(?:({PLATFORM})\/)?(?:{IDENT})$"


class ClamAV(EnginePattern):
    pattern = rf"""^
        (?:(?P<PREFIX>BC|Clamav))?
        (?:(\.|^)({PLATFORM}))?
        (?:(\.|^)(?P<LABELS>[-\w]+))
        (?:(\.|^)(?P<FAMILY>\w+)(?:(\:\w|\/\w+))*(?:-(?P<VARIANT>[\-0-9]+)))?$"""


class DrWeb(EnginePattern):
    pattern = rf"""^
    ((?i:{HEURISTICS})(\s+(of\s*)?)?)?
              (?:(\.|\A|\b)(?i:({PLATFORM})))?
              (?:(\.|\A|\b)(?i:{LABELS}))?
              (?:(\.|\b)( # MulDrop6.38732 can appear alone or in front of another `.`
                  (?P<FAMILY>[A-Za-z][-\w\.]+?)
                  (?:\.|\Z) # and either end or continue with `.`
                  (?P<VARIANT>[0-9]+)?
                  (\.?(?P<SUFFIX>(origin|based)))?))?$"""


class Ikarus(EnginePattern):
    pattern = rf"""
        ^({OBFUSCATIONS}\.)?
              (?:{HEURISTICS}\:?)?
              ((?:\A|\.|\b)({LABELS}|{EXPLOITS}|{PLATFORM}))*?
              (\.{IDENT})?$"""


class Jiangmin(EnginePattern):
    pattern = rf"""^(?:{HEURISTICS}:?)?
              (?:(?:\b|\.|/|^)({OBFUSCATIONS}|{LABELS}|{PLATFORM}))*
              (?:(?:\.|/|^|\b)
                  ((?P<FAMILY>(CVE-[\d-]*|[A-Z]\w*))(?P<SUFFIX>(\-(\w+)))?(\.|\Z))?
                  ((?P<VARIANT>((\d+\.)?\w*)))?)?$"""


class K7(EnginePattern):
    pattern = rf"^{LABELS}?\s*(\s*\(\s*(?P<VARIANT>[a-f0-9]+)\s*\))?"


class Lionic(EnginePattern):
    pattern = rf"^{LABELS}?(?:(^|\.)(?:{PLATFORM}))?((\.|^){IDENT})?$"


class NanoAV(EnginePattern):
    pattern = rf"""^
        ({LABELS})?
              ((?:\.)(?P<NANO_TYPE>(Macro|Text|Url)))?
              ((?:\.)(?:{PLATFORM}))*?
              ((?:\.|\A|\b){IDENT})$"""


class Qihoo360(EnginePattern):
    pattern = rf"""
        ^({HEURISTICS}(/|((?<=VirusOrg)\.)))?
              (
                  ((\.|\b|\A)({MACROS}|{LANGS}|{OSES}|{ARCHIVES}))
                  |(\.|\b|\/|\A){LABELS}
                  |((\.|\b)(QVM\d*(\.\d)?(\.[0-9A-F]+)?))
              )*
              ((\.|/){IDENT})?$"""


class QuickHeal(EnginePattern):
    pattern = rf"""
        ^(?:{HEURISTICS}\.)?
              # This trailing (\)$) handle wierd cases like 'Adware)' or 'PUP)'
              ((?:\.|^){LABELS}(\)$)?)?
              ((?:\.|^)(?:{PLATFORM}))?
              ((?:\.|\/|^)
                  ((?P<FAMILY>[-\w]+))
                  (\.(?P<VARIANT>\w+))?
                  (\.(?P<SUFFIX>\w+))?)?$"""


class Rising(EnginePattern):
    pattern = rf"""^
            {LABELS}?
            (
                ((?:^|\/|\.)(?:{PLATFORM})) |
                ((?:\.|\/)(?P<FAMILY>[A-Z][\-\w]+))
            )*
            (?:(?P<VARIANTSEP>(\#|@|!|\.))(?P<VARIANT>.*))
    $"""


class Virusdie(EnginePattern):
    pattern = rf"""^
        (?:{HEURISTICS})?
        (?:(?:^|\.){LABELS})?
        (?:(?:^|\.){PLATFORM})?
        (?:(?:^|\.){IDENT})
    $"""
