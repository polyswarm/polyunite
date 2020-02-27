import re
from typing import Any, Dict, List, Optional

from polyunite.utils import GROUP_COLORS, EngineSchemes, reset, trx
from polyunite.vocab import (
    ARCHIVES,
    BEHAVIORS,
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
        values = {}
        if self.match:
            for k, v in self.match.groupdict().items():
                if not k.isupper():
                    raise ValueError("Must supply upper-cased group names")
                values[k] = v if v else ''
        return values

    def __repr__(self):
        fields = {f: getattr(self, f, None) for f in ('name', 'operating_system', 'script', 'label')}
        return '<{av_vendor}.scheme({fields})>'.format(
            av_vendor=self.av_vendor, fields=", ".join([f'{f}={v}' for f, v in fields.items() if v])
        )

    def colorize(self) -> str:
        """Colorize a classification string"""
        if not self.match:
            return None

        ss = self.classification_name

        for name, mt in self.match.groupdict().items():
            if not mt or name not in GROUP_COLORS:
                continue
            # be lazyi in finding the new location mod ANSI color codes.
            idx = ss.rfind(mt)
            end = idx + len(mt)
            ss = ss[:idx] + GROUP_COLORS[name] + mt + ('' if reset in ss[end:] else reset) + ss[end:]

        return ss

    def match_raw(self, rgx) -> Optional[re.Match]:
        """Return a match on the raw classification name string"""
        return re.match(rgx, self.classification_name, re.IGNORECASE)

    # override these methods to change how an engine sources particular features.
    # extracted from the source match.
    @property
    def classification_name(self) -> str:
        return self.match.string if self.match else None

    @property
    def av_vendor(self) -> str:
        return str(self.__class__.__name__)

    @property
    def heuristic(self) -> Optional[bool]:
        return self.values.get('VARIANT', '').lower().startswith('gen') or any(
            HEURISTICS.find(value=f)
            for f in list(map(trx, map(self.values.get, ('HEURISTICS', 'FIELDS', 'FAMILY', 'LABELS'))))
            if f
        )

    @property
    def malice_unlikely(self) -> bool:
        raw = self.classification_name
        if isinstance(raw, str):
            lower = trx(raw.lower()).replace('-', '')
            return any(word in lower for word in {'eicar', 'notavirus', 'testfile', 'testvirus'})
        return None

    @property
    def name(self) -> str:
        family = self.values.get('FAMILY', None)
        prefix = [family] if family and len(family) > 2 else [
            v for k, v in self.match.groupdict().items()
            if k in {'LANGS', 'MACROS', 'OPERATING_SYSTEMS', 'ARCHIVES', 'LABELS'} if v
        ]
        result = '.'.join(filter(None, prefix + [self.values.get('VARIANT', self.values.get('SUFFIX'))]))
        return result

    @property
    def operating_system(self) -> str:
        return OSES.find(self.values)

    @property
    def language(self) -> str:
        return LANGS.find(self.values)

    @property
    def macro(self) -> str:
        return MACROS.find(self.values)

    @property
    def labels(self) -> List[str]:
        return LABELS.find(self.values, every=True)


class Alibaba(BaseNameScheme):
    rgx = re.compile(rf"^(?:{LABELS}:)?(?:({PLATFORM})\/)?(?:{IDENT})$", re.IGNORECASE)


class ClamAV(BaseNameScheme):
    rgx = re.compile(
        r"^(?:(?P<PREFIX>BC|Clamav))?"
        rf"(?:(\.|^)({PLATFORM}))?"
        r"(?:(\.|^)(?P<LABELS>[-\w]+))"
        r"(?:(\.|^)(?P<FAMILY>\w+)(?:(\:\w|\/\w+))*(?:-(?P<VARIANT>[\-0-9]+)))?$", re.IGNORECASE
    )


class DrWeb(BaseNameScheme):
    rgx = re.compile(
        rf"""^
        ((?i:{HEURISTICS})(\s+(of\s*)?)?)?
        ((\.|\A|\b)(?i:({PLATFORM})))?
        ((\.|\A|\b)(?i:{LABELS}))?
        ((\.|\b)( # MulDrop6.38732 can appear alone or in front of another `.`
            (?P<FAMILY>[A-Za-z][-\w\.]+?)
            (\.|\Z) # and either end or continue with `.`
            (?P<VARIANT>[0-9]+)?
            (\.?(?P<SUFFIX>(origin|based)))?
        ))?
        $""", re.VERBOSE
    )


class Ikarus(BaseNameScheme):
    rgx = re.compile(
        rf"""^
        ({OBFUSCATIONS}\.)?
        (?P<HEURISTIC>[-\w+]+?\:)?
        ({LABELS})?
        ((\.){EXPLOITS})?
        ((^|[^\w]){PLATFORM})?
        (\.{IDENT})?
        $""", re.VERBOSE
    )


class Jiangmin(BaseNameScheme):
    rgx = re.compile(
        rf"""^
        (?P<HEURISTIC>(Variant|heur:))?
        ((\b|\.|\/|\A)({OBFUSCATIONS}|{LABELS}|{PLATFORM}))*
        ((\.|\/|\A|\b)
            ((?P<FAMILY>(CVE-[\d-]*|[A-Z]\w*))(?P<SUFFIX>(\-(\w+)))?(\.|\Z))?
            ((?P<VARIANT>((\d+\.)?\w*)))?
        )?$""", re.VERBOSE
    )


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
        rf"""^
        ({LABELS})?
        ((\.)(?P<NANO_TYPE>(Macro|Text|Url)))?
        ((\.)(?:{PLATFORM}))*?
        ((\.|\A|\b){IDENT})
        $""", re.VERBOSE
    )


class Qihoo360(BaseNameScheme):
    rgx = re.compile(
        rf"""^
        ((?P<HEURISTIC>(VirusOrg|Generic|HEUR))(/|((?<=VirusOrg)\.)))?
        (
            ((\.|\b|^)({MACROS}|{LANGS}|{OSES}|{ARCHIVES}))
            |(\.|\b|/|^){LABELS}
            |((\.|\b)(QVM\d*(\.\d)?(\.[0-9A-F]+)?))
        )*?
        ((\.|/){IDENT})?$""", re.VERBOSE
    )


class QuickHeal(BaseNameScheme):
    rgx = re.compile(
        rf"""^
        ({HEURISTICS}\.)?
        # This trailing (\)$) handle wierd cases like 'Adware)' or 'PUP)'
        ((\.|^){LABELS}(\)$)?)?
        ((\.|^)(?:{PLATFORM}))?
        ((\.|\/|^)
            ((?P<FAMILY>[-\w]+))
            (\.(?P<VARIANT>\w+))?
            (\.(?P<SUFFIX>\w+))?)?
        $""", re.VERBOSE
    )


class Rising(BaseNameScheme):
    rgx = re.compile(
        rf"""^
        ({LABELS})?
        ((
             (((?:^|\/|\.)(?:{PLATFORM}))) |
             ((\.|\/) (?P<FAMILY>[A-Z][\-\w]+)))
        )*
        ((?P<VARIANTSEP>(\#|\@|\!|\.))(?P<VARIANT>.*))
        $""", re.VERBOSE
    )


class Virusdie(BaseNameScheme):
    rgx = re.compile(
        rf"^({HEURISTICS})?((^|\.){LABELS})?((^|\.){PLATFORM})?"
        rf"((^|\.){IDENT})$"
    )
