from itertools import chain
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


class BaseNameScheme:
    match: Optional[re.Match]
    values: Dict[str, Any]
    rgx: re.Pattern

    @classmethod
    def __init_subclass__(cls):
        super().__init_subclass__()
        Schemes[cls.__name__] = cls

    def __init__(self, classification: str):
        self.values = self.build_values(classification)

    def build_values(self, classification):
        self.match = self.rgx.match(classification)
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

    def __repr__(self):
        keys = ('name', 'operating_system', 'script', 'labels')
        fields = ', '.join('='.join(map(lambda f: (f, getattr(self, f, None)), keys)))
        return f'<{self.av_vendor}.scheme({fields})>'

    @property
    def classification_name(self) -> Optional[str]:
        return self.match and self.match.string

    @property
    def av_vendor(self) -> str:
        return str(self.__class__.__name__)

    @property
    def heuristic(self) -> Optional[bool]:
        keys = ('HEURISTICS', 'FAMILY', 'LABELS', 'VARIANT')
        return any(map(any, map(HEURISTICS.find, filter(None, map(self.values.get, keys)))))

    @property
    def peripheral(self) -> bool:
        labels = {'test', 'nonmalware', 'greyware', 'shellcode', 'security_assessment_tool'}
        return not self.labels.isdisjoint(labels)

    @property
    def name(self) -> str:
        try:
            groups = ('FAMILY', 'LANGS', 'MACROS', 'OPERATING_SYSTEMS', 'LABELS')
            suffix = self.values.get('VARIANT') or self.values.get('SUFFIX', '')
            return next(filter(None, map(self.values.get, groups))) + (suffix and '.' + suffix)
        except StopIteration:
            return self.classification_name

    @property
    def operating_system(self) -> str:
        return first_match(OSES.find(self.values))

    @property
    def language(self) -> str:
        return first_match(LANGS.find(self.values))

    @property
    def macro(self) -> str:
        return first_match(MACROS.find(self.values))

    @property
    def labels(self) -> List[str]:
        return set((m.lastgroup for m in LABELS.find(self.values)))


class Alibaba(BaseNameScheme):
    rgx = re.compile(rf"^(?:{LABELS}:)?(?:({PLATFORM})\/)?(?:{IDENT})$", re.IGNORECASE)


class ClamAV(BaseNameScheme):
    rgx = re.compile(
        r"^(?:(?P<PREFIX>BC|Clamav))?"
        rf"(?:(\.|^)({PLATFORM}))?"
        r"(?:(\.|^)(?P<LABELS>[-\w]+))"
        r"(?:(\.|^)(?P<FAMILY>\w+)(?:(\:\w|\/\w+))*(?:-(?P<VARIANT>[\-0-9]+)))?$", re.IGNORECASE)


class DrWeb(BaseNameScheme):
    rgx = re.compile(
        rf"""^((?i:{HEURISTICS})(\s+(of\s*)?)?)?
              ((\.|\A|\b)(?i:({PLATFORM})))?
              ((\.|\A|\b)(?i:{LABELS}))?
              ((\.|\b)( # MulDrop6.38732 can appear alone or in front of another `.`
                  (?P<FAMILY>[A-Za-z][-\w\.]+?)
                  (\.|\Z) # and either end or continue with `.`
                  (?P<VARIANT>[0-9]+)?
                  (\.?(?P<SUFFIX>(origin|based)))?
              ))?$""", re.VERBOSE)


class Ikarus(BaseNameScheme):
    rgx = re.compile(
        rf"""^({OBFUSCATIONS}\.)?
              (?:{HEURISTICS}\:?)?
              ((\A|\.|\b)({LABELS}|{EXPLOITS}|{PLATFORM}))*
              (\.{IDENT})?$""", re.VERBOSE)


class Jiangmin(BaseNameScheme):
    rgx = re.compile(
        rf"""^(?:{HEURISTICS}:?)?
              ((\b|\.|\/|\A)({OBFUSCATIONS}|{LABELS}|{PLATFORM}))*
              ((\.|\/|\A|\b)
                  ((?P<FAMILY>(CVE-[\d-]*|[A-Z]\w*))(?P<SUFFIX>(\-(\w+)))?(\.|\Z))?
                  ((?P<VARIANT>((\d+\.)?\w*)))?
              )?$""", re.VERBOSE)


class K7(BaseNameScheme):
    rgx = re.compile(rf"^(?i:{LABELS})\s*(\s*\(\s*(?P<VARIANT>[a-f0-9]+)\s*\))?")

    @property
    def name(self):
        variant = self.values.get("VARIANT")
        return self.values['LABELS'] + (f':{variant}' if variant else '')


class Lionic(BaseNameScheme):
    rgx = re.compile(rf"^({LABELS})?" rf"((^|\.)(?:{PLATFORM}))?" rf"((\.|^){IDENT})?$", re.IGNORECASE)


class NanoAV(BaseNameScheme):
    rgx = re.compile(
        rf"""^({LABELS})?
              ((\.)(?P<NANO_TYPE>(Macro|Text|Url)))?
              ((\.)(?:{PLATFORM}))*?
              ((\.|\A|\b){IDENT})$""", re.VERBOSE)


class Qihoo360(BaseNameScheme):
    rgx = re.compile(
        rf"""^((?P<HEURISTIC>(VirusOrg|Generic|HEUR))(/|((?<=VirusOrg)\.)))?
              (
                  ((\.|\b|^)({MACROS}|{LANGS}|{OSES}|{ARCHIVES}))
                  |(\.|\b|/|^){LABELS}
                  |((\.|\b)(QVM\d*(\.\d)?(\.[0-9A-F]+)?))
              )*?
              ((\.|/){IDENT})?$""", re.VERBOSE)


class QuickHeal(BaseNameScheme):
    rgx = re.compile(
        rf"""^({HEURISTICS}\.)?
              # This trailing (\)$) handle wierd cases like 'Adware)' or 'PUP)'
              ((\.|^){LABELS}(\)$)?)?
              ((\.|^)(?:{PLATFORM}))?
              ((\.|\/|^)
                  ((?P<FAMILY>[-\w]+))
                  (\.(?P<VARIANT>\w+))?
                  (\.(?P<SUFFIX>\w+))?)?$""", re.VERBOSE)


class Rising(BaseNameScheme):
    rgx = re.compile(
        rf"""^({LABELS})?
              ((
                  (((?:^|\/|\.)(?:{PLATFORM}))) |
                  ((\.|\/) (?P<FAMILY>[A-Z][\-\w]+)))
              )*
              ((?P<VARIANTSEP>(\#|\@|\!|\.))(?P<VARIANT>.*))$""", re.VERBOSE)


class Virusdie(BaseNameScheme):
    rgx = re.compile(rf"^({HEURISTICS})?((^|\.){LABELS})?((^|\.){PLATFORM})?" rf"((^|\.){IDENT})$")
