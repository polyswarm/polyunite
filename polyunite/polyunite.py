from itertools import chain, islice
import re
from typing import Any, Dict, List, Optional

from polyunite.utils import GROUP_COLORS, EngineSchemes, reset
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

Schemes = EngineSchemes()


def first_match(gen):
    return next((m.lastgroup for m in gen), None)


def build_pattern(pattern_str: str, options=re.VERBOSE):
    return re.compile(pattern_str, options)


class BaseNameScheme:
    match: Optional[re.Match]
    values: Dict[str, Any]
    pattern: re.Pattern

    @classmethod
    def __init_subclass__(cls):
        super().__init_subclass__()
        Schemes[cls.__name__] = cls

    def __init__(self, classification: str):
        self.values = self.build_values(classification)

    def build_values(self, classification):
        self.match = self.pattern.search(classification)
        if self.match:
            return {k: v for k, v in self.match.groupdict().items() if v}

    def colorize(self) -> str:
        """Colorize a classification string"""
        ss = self.classification_name
        if ss:
            # interleave the color, match & reset between the part before & after the match (from rpartition)
            for name, match in filter(lambda kv: kv[0] in GROUP_COLORS, self.values.items()):
                ss = ''.join(chain(*zip(ss.rpartition(match), (GROUP_COLORS[name], reset, ''))))
        return ss

    @property
    def classification_name(self) -> Optional[str]:
        return self.match and self.match.string

    @property
    def av_vendor(self) -> str:
        return str(self.__class__.__name__)

    @property
    def heuristic(self) -> Optional[bool]:
        keys = ('HEURISTICS', 'FAMILY', 'LABELS', 'VARIANT')
        pattern = re.compile(HEURISTICS.compile(1), re.IGNORECASE)
        return any(map(pattern.search, filter(None, map(self.values.get, keys))))

    @property
    def peripheral(self) -> bool:
        return not self.labels.isdisjoint({
            'test', 'nonmalware', 'greyware', 'shellcode', 'security_assessment_tool'
        })

    @property
    def name(self) -> str:
        try:
            keys = ('FAMILY', 'LANGS', 'MACROS', 'OPERATING_SYSTEMS', 'LABELS')
            prefix = next(filter(None, map(self.values.get, keys)))
            suffix = self.values.get('VARIANT') or self.values.get('SUFFIX')
            return prefix + (f'.{suffix}' if suffix else '')
        except StopIteration:
            return self.classification_name

    def nmatch(self, name):
        span = self.values.get(name)
        return span and next((k for k, v in self.values.items() if k != name and v == span), None)

    @property
    def operating_system(self) -> str:
        return self.nmatch(OSES.name)

    @property
    def language(self) -> str:
        return self.nmatch(LANGS.name)

    @property
    def macro(self) -> str:
        return self.nmatch(MACROS.name)

    @property
    def labels(self) -> List[str]:
        group = self.values.get(LABELS.name, r'\Z\A')
        return set(map(lambda m: m.lastgroup, re.finditer(LABELS.compile(1), group)))


class Alibaba(BaseNameScheme):
    pattern = build_pattern(rf"^(?:{LABELS}:)?(?:({PLATFORM})\/)?(?:{IDENT})$")


class ClamAV(BaseNameScheme):
    pattern = build_pattern(rf"""^
        (?:(?P<PREFIX>BC|Clamav))?
        (?:(\.|^)({PLATFORM}))?
        (?:(\.|^)(?P<LABELS>[-\w]+))
        (?:(\.|^)(?P<FAMILY>\w+)(?:(\:\w|\/\w+))*(?:-(?P<VARIANT>[\-0-9]+)))?$""")


class DrWeb(BaseNameScheme):
    pattern = build_pattern(rf"""^
    ((?i:{HEURISTICS})(\s+(of\s*)?)?)?
              (?:(\.|\A|\b)(?i:({PLATFORM})))?
              (?:(\.|\A|\b)(?i:{LABELS}))?
              (?:(\.|\b)( # MulDrop6.38732 can appear alone or in front of another `.`
                  (?P<FAMILY>[A-Za-z][-\w\.]+?)
                  (?:\.|\Z) # and either end or continue with `.`
                  (?P<VARIANT>[0-9]+)?
                  (\.?(?P<SUFFIX>(origin|based)))?))?$""")


class Ikarus(BaseNameScheme):
    pattern = build_pattern(rf"""
        ^({OBFUSCATIONS}\.)?
              (?:{HEURISTICS}\:?)?
              ((?:\A|\.|\b)({LABELS}|{EXPLOITS}|{PLATFORM}))*?
              (\.{IDENT})?$""")


class Jiangmin(BaseNameScheme):
    pattern = build_pattern(
        rf"""^(?:{HEURISTICS}:?)?
              (?:(?:\b|\.|/|^)({OBFUSCATIONS}|{LABELS}|{PLATFORM}))*
              (?:(?:\.|/|^|\b)
                  ((?P<FAMILY>(CVE-[\d-]*|[A-Z]\w*))(?P<SUFFIX>(\-(\w+)))?(\.|\Z))?
                  ((?P<VARIANT>((\d+\.)?\w*)))?)?$""")


class K7(BaseNameScheme):
    pattern = build_pattern(rf"^{LABELS}?\s*(\s*\(\s*(?P<VARIANT>[a-f0-9]+)\s*\))?")


class Lionic(BaseNameScheme):
    pattern = build_pattern(rf"^{LABELS}?(?:(^|\.)(?:{PLATFORM}))?((\.|^){IDENT})?$")


class NanoAV(BaseNameScheme):
    pattern = build_pattern(rf"""^
        ({LABELS})?
              ((?:\.)(?P<NANO_TYPE>(Macro|Text|Url)))?
              ((?:\.)(?:{PLATFORM}))*?
              ((?:\.|\A|\b){IDENT})$""")


class Qihoo360(BaseNameScheme):
    pattern = build_pattern(rf"""
        ^({HEURISTICS}(/|((?<=VirusOrg)\.)))?
              (
                  ((\.|\b|\A)({MACROS}|{LANGS}|{OSES}|{ARCHIVES}))
                  |(\.|\b|\/|\A){LABELS}
                  |((\.|\b)(QVM\d*(\.\d)?(\.[0-9A-F]+)?))
              )*
              ((\.|/){IDENT})?$""")


class QuickHeal(BaseNameScheme):
    pattern = build_pattern(rf"""
        ^(?:{HEURISTICS}\.)?
              # This trailing (\)$) handle wierd cases like 'Adware)' or 'PUP)'
              ((?:\.|^){LABELS}(\)$)?)?
              ((?:\.|^)(?:{PLATFORM}))?
              ((?:\.|\/|^)
                  ((?P<FAMILY>[-\w]+))
                  (\.(?P<VARIANT>\w+))?
                  (\.(?P<SUFFIX>\w+))?)?$""")


class Rising(BaseNameScheme):
    pattern = build_pattern(rf"""^
            {LABELS}?
            (
                ((?:^|\/|\.)(?:{PLATFORM})) |
                ((?:\.|\/)(?P<FAMILY>[A-Z][\-\w]+))
            )*
            (?:(?P<VARIANTSEP>(\#|@|!|\.))(?P<VARIANT>.*))
    $""")


class Virusdie(BaseNameScheme):
    pattern = build_pattern(rf"""^
        (?:{HEURISTICS})?
        (?:(?:^|\.){LABELS})?
        (?:(?:^|\.){PLATFORM})?
        (?:(?:^|\.){IDENT})
    $""")
