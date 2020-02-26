import re
from typing import Any, Dict, List, Optional

from polyunite.utils import GROUP_COLORS, EngineSchemes, reset, trx
from polyunite.vocab import (
    ARCHIVES,
    EXPLOITS,
    HEURISTICS,
    OBFUSCATIONS,
    BEHAVIORS,
    IDENT,
    LABELS,
    LANGS,
    MACROS,
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
            for f in list(map(trx, map(self.values.get, ('HEURISTIC', 'FIELDS', 'FAMILY', 'LABEL'))))
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
        return self.values.get('NAME')

    @property
    def fullname(self) -> str:
        return self.values.get('FAMILY') or (
            '.'.join((self.values.get('NAME', ''), self.values.get('VARIANT', '')))
        ) or None

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
    def label(self) -> List[str]:
        return LABELS.find(self.values, every=True)

    def build_values(self, classification):
        self.match = self.rgx.match(classification)
        values = {}
        if self.match:
            for k, v in self.match.groupdict().items():
                if not k.isupper():
                    raise ValueError("Must supply upper-cased group names")
                values[k] = v if v else ''
        return values


class Alibaba(BaseNameScheme):
    rgx = re.compile(rf"^({LABELS}:)?({PLATFORM}\/)?({IDENT})$", re.IGNORECASE)


class ClamAV(BaseNameScheme):
    rgx = re.compile(
        r"^((?P<PREFIX>BC|Clamav))?"
        rf"((\.|^){PLATFORM})?"
        r"((\.|^)(?P<LABEL>[-\w]+))"
        r"((\.|^)(?P<NAME>((?P<FAMILY>\w+)((\:\w)|(\/\w+))*(\-(?P<VARIANT>[\-0-9]+)))))?$", re.IGNORECASE
    )


class DrWeb(BaseNameScheme):
    rgx = re.compile(
        rf"^((?i:{HEURISTICS})(\s+(of\s*)?)?)?"
        rf"((\.|\A)(?i:({OSES.combine('PLATFORM', ARCHIVES, MACROS, LANGS)})))?"
        rf"((\.|\A)(?i:{LABELS}))?"
        r"((\.|\b)((?P<NAME>("
        r"(?P<FAMILY>[A-Za-z][-\w\.]+?)"
        r"((\.|$)(?P<VARIANT>[0-9]+))?"
        r"(\.?(?P<SUFFIX>(origin|based)))?))))?$"
    )


class Ikarus(BaseNameScheme):
    rgx = re.compile(
        rf"^({OBFUSCATIONS}\.)?"
        rf"(?P<HEURISTIC>[-\w+]+?\:)?"
        r"((?P<LABEL>[\w-]*?))?"
        rf"((\.){EXPLOITS})?"
        rf"((^|[^\w]){PLATFORM})?"
        rf"(\.{IDENT})?$", re.IGNORECASE
    )


class Jiangmin(BaseNameScheme):
    rgx = re.compile(
        r"^(?P<HEURISTIC>(Variant|heur:))?"
        rf"((\b|\.|\A)({OBFUSCATIONS}))?"
        rf"((\b|\.|\/|\A)((?i:{LABELS})|({PLATFORM})))*"
        r"((\.|\/|\A|\b)(?P<NAME>("
        r"((?P<FAMILY>(CVE-[\d-]*|\w+))(?P<SUFFIX>(\-(\w+)))?(\.|$))?"
        r"((?P<VARIANT>((\d+\.)?\w*)))?)))?$", re.IGNORECASE
    )


class K7(BaseNameScheme):
    rgx = re.compile(rf"^(?i:{LABELS})\s*(\s*\(\s*(?P<VARIANT>[a-f0-9]+)\s*\))?")

    @property
    def name(self):
        variant = self.values.get("VARIANT")
        return self.values['LABEL'] + (f':{variant}' if variant else '')


class Lionic(BaseNameScheme):
    rgx = re.compile(rf"^({LABELS})?" rf"((^|\.){PLATFORM})?" rf"((\.|^){IDENT})?$", re.IGNORECASE)


class NanoAV(BaseNameScheme):
    rgx = re.compile(
        rf"^({LABELS})?"
        r"((\.)(?P<NANO_TYPE>(Macro|Text|(Url\.(\w+)))))?"
        rf"((\.)({PLATFORM}))?"
        rf"((\.|\A|\b){IDENT})$", re.IGNORECASE
    )


class Qihoo360(BaseNameScheme):
    rgx = re.compile(
        r"^((?P<HEURISTIC>(VirusOrg|Generic|HEUR))(/|((?<=VirusOrg)\.)))?"
        r"(macro|tif)?"
        rf"(((\.|\b)(url|iframe|{MACROS}|{LANGS}|{OSES}|{ARCHIVES}))|(\.|\b|/){LABELS}|"
        r"((\.|\b)(QVM\d*(\.\d)?(\.[0-9A-F]+)?)))*"
        rf"((\.|/){IDENT})?$", re.IGNORECASE
    )


class QuickHeal(BaseNameScheme):
    rgx = re.compile(
        rf"^({HEURISTICS}\.)?"
        # This trailing (\)$) handle wierd cases like 'Adware)' or 'PUP)'
        rf"((\.|^){LABELS}(\)$)?)?"
        rf"((\.|^)({PLATFORM}))?"
        r"((\.|\/|^)(?P<NAME>(((?P<FAMILY>[-\w]+))(\.(?P<VARIANT>\w+))?(\.(?P<SUFFIX>\w+))?)))?$",
        re.IGNORECASE
    )


class Rising(BaseNameScheme):
    rgx = re.compile(
        rf"^({LABELS})?"
        rf"(((((^|\/|\.)({OSES.combine('PLATFORM', ARCHIVES, MACROS, LANGS, include=['System', 'Macro'])})))"
        r"|((\.|\/)(?P<FAMILY>[\-\w]+))))*"
        rf"((?P<VARIANTSEP>(\#|\@|\!|\.))(?P<VARIANT>.*))$", re.IGNORECASE
    )

    @property
    def name(self) -> str:
        return self.values.get('FAMILY', '') + self.values.get('VARIANTSEP',
                                                               '') + self.values.get('VARIANT', '')


class Virusdie(BaseNameScheme):
    rgx = re.compile(
        rf"^({HEURISTICS})?((^|\.){LABELS})?((^|\.){PLATFORM})?"
        rf"((^|\.){IDENT})$", re.IGNORECASE
    )
