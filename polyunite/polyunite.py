from collections import UserDict
import re
import string
from typing import Any, Dict, List, Optional

from polyunite.utils import GROUP_COLORS, reset, trx
from polyunite.vocab import (
    ARCHIVES,
    EXPLOITS,
    HEURISTICS,
    LABELS,
    LANGS,
    MACROS,
    OSES,
    PLATFORM_REGEXES,
)


class EngineSchemes(UserDict):
    """A fancy dictionary for holding each engine, with easy lookup"""
    def __setitem__(self, k, v):
        return super().__setitem__(trx(k), v)

    def __getitem__(self, k):
        return super().__getitem__(trx(k))

    def __contains__(self, k):
        return super().__contains__(trx(k))

    def parse(self, name, classification: str):
        if name in self:
            return self[name](classification)
        return None


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
    rgx = re.compile(
        rf"^((?P<LABEL>\w+):)?"
        rf"({PLATFORM_REGEXES}\/)?"
        rf"(?P<NAME>((?P<FAMILY>[^.]+))"
        rf"(\.(?P<VARIANT>.*))?)$",
        flags=re.IGNORECASE
    )


class ClamAV(BaseNameScheme):
    rgx = re.compile(
        r"^((?P<PREFIX>BC|Clamav))?"
        rf"((\.|^){PLATFORM_REGEXES})?"
        r"((\.|^)(?P<LABEL>[-\w]+))"
        r"((\.|^)(?P<NAME>((?P<FAMILY>\w+)((\:\w)|(\/\w+))*(\-(?P<VARIANT>[\-0-9]+)))))?$", re.IGNORECASE
    )


class DrWeb(BaseNameScheme):
    rgx = re.compile(
        rf"^((?i:{HEURISTICS})(\s+(of\s*)?)?)?"
        rf"((\.|\b)({OSES.combine('PLATFORM', ARCHIVES, MACROS, LANGS)}))?"
        rf"((\.|\b)(?P<LABEL>[A-Za-z]*))?"
        r"((\.|\b)((?P<NAME>((?P<FAMILY>[A-Za-z][-\w\.]+?)((\.|$)(?P<VARIANT>[0-9]+))?(\.?(?P<SUFFIX>(origin|based)))?))))?$"
    )


class Ikarus(BaseNameScheme):
    rgx = re.compile(
        r"^((?P<OBFUSCATION>Packed)\.)?"
        rf"(?P<HEURISTIC>[-\w+]+?\:)?"
        r"((?P<LABEL>[\w-]*?))?"
        rf"((^|[^\w]){PLATFORM_REGEXES})?"
        r"(\.(?P<NAME>..+))?$"
    )


class Jiangmin(BaseNameScheme):
    rgx = re.compile(
        r"^(?P<HEURISTIC>(Variant|heur\:))?"
        rf"((\.|\/|^)((?i:{LABELS})|({PLATFORM_REGEXES})))*"
        r"((\.|\/|^)(?P<NAME>(((?P<FAMILY>[-\w]+)(\.|$))?((?P<VARIANT>((\d+\.)?\w*)))?)))$"
    )


class K7(BaseNameScheme):
    rgx = re.compile(rf"^(?i:{LABELS})\s*(\s*\(\s*(?P<VARIANT>[a-f0-9]+)\s*\))?")

    @property
    def name(self):
        variant = self.values.get("VARIANT")
        return self.values['LABEL'] + (f':{variant}' if variant else '')

class Lionic(BaseNameScheme):
    rgx = re.compile(
        rf"^({LABELS})?"
        rf"((^|\.){PLATFORM_REGEXES})?"
        r"((\.|^)(?P<NAME>((?P<FAMILY>[-\w]+)"
        r"(\.(?P<VARIANT>\w*))?"
        r"(\!(?P<SUFFIX>\w.*))?)))?$", re.IGNORECASE
    )


class NanoAV(BaseNameScheme):
    rgx = re.compile(
        r"^((?P<EXPLOIT>Exploit|Exp)\.)?"
        rf"((?i:{LABELS}))?"
        rf"((\.)({PLATFORM_REGEXES}|\w+))?"
        r"((\.|^)(?P<NAME>((?P<FAMILY>[\w-]+)(\.(?P<VARIANT>[a-z]+)))))$", re.IGNORECASE)


class Qihoo360(BaseNameScheme):
    rgx = re.compile(
        rf"^(({PLATFORM_REGEXES}(\.|\/))+"
        r"|((?P<LABEL>[-\w]+)\.)"
        r"|((?P<HEURISTIC>Generic|HEUR)(\/)(QVM\d*\.(\d\.)?([0-9A-F]+\.)?)?))*?"
        r"((?<=\.)(?P<NAME>((?P<FAMILY>[-\w]+)\.)?((?P<VARIANT>\w+))))?$", re.IGNORECASE
    )


class QuickHeal(BaseNameScheme):
    rgx = re.compile(
        rf"^({HEURISTICS}\.)?((?P<EXPLOIT>Exploit|Exp)\.)?"
        # This trailing (\)$) handle wierd cases like 'Adware)' or 'PUP)'
        rf"((\.|^){LABELS}(\)$)?)?"
        rf"((\.|^)({PLATFORM_REGEXES}))?"
        r"((\.|\/|^)(?P<NAME>(((?P<FAMILY>[-\w]+))(\.(?P<VARIANT>\w+))?(\.(?P<SUFFIX>\w+))?)))?$", re.IGNORECASE
    )


class Rising(BaseNameScheme):
    rgx = re.compile(
        rf"^({LABELS})?"
        rf"(((((^|\/|\.)({OSES.combine('PLATFORM', ARCHIVES, MACROS, LANGS)})))"
        r"|((\.|\/)(?P<FAMILY>[\-\w]+))))*"
        rf"((?P<VARIANTSEP>(\#|\@|\!|\.))(?P<VARIANT>.*))$", re.IGNORECASE
    )

    @property
    def name(self) -> str:
        return self.values.get('FAMILY', '') + self.values.get('VARIANTSEP',
                                                               '') + self.values.get('VARIANT', '')


class Virusdie(BaseNameScheme):
    rgx = re.compile(
        rf"^({HEURISTICS})?((^|\.){LABELS})?((^|\.){PLATFORM_REGEXES})?"
        r"((^|\.)(?P<NAME>((?P<FAMILY>[\.\w]+)?(\.(?P<VARIANT>\w+))?)?))$", re.IGNORECASE)
