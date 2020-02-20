from collections import UserDict
import re
from typing import Any, Dict, Optional

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
        self.match = self.rgx.match(classification)
        self.build_values(self.match)

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
        for name, mt in ((k, v) for k, v in self.match.groupdict().items() if v):
            # be lazyi in finding the new location mod ANSI color codes.
            idx = ss.rfind(mt)
            end = idx + len(mt)
            ss = ss[:idx] + GROUP_COLORS.get(name, '') + mt + (reset if ss[end:].find(reset) == -1 else
                                                               '') + ss[end:]
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
        if self.values.get('HEURISTIC'):
            return True
        else:
            for field in filter(None, map(self.values.get, ('LABEL', 'FIELDS', 'NAME', 'FAMILY'))):
                if HEURISTICS.find(value=field):
                    return True
        return False

    @property
    def malice_unlikely(self) -> bool:
        """*IMPERFECT* predicate for checking if a classification string suggests the file isn't malware"""
        if self.match_raw(r'(\b|[^a-z])(not-a-virus|notavirus|eicar|test|testfile|testvirus)([^a-z]|\b)'):
            return True
        return self.label == 'test'

    @property
    def name(self) -> str:
        return self.values.get('NAME') or self.values.get('FAMILY')

    @property
    def operating_system(self) -> str:
        return OSES.find(self.values)

    @property
    def script(self) -> str:
        return LANGS.find(self.values)

    @property
    def label(self) -> str:
        return LABELS.find(self.values)

    def build_values(self, match):
        self.values = {}
        if match:
            for k, v in match.groupdict().items():
                if not k.isupper():
                    raise ValueError("Must supply upper-cased group names")
                self.values[k] = v if v else ''


class Alibaba(BaseNameScheme):
    rgx = re.compile(
        rf"^((?P<LABEL>\w+):)?"
        rf"({PLATFORM_REGEXES}\/)?"
        rf"((?P<NAME>[^.]+))"
        rf"(\.(?P<VENDORID>.*))?$",
        flags=re.IGNORECASE
    )


class ClamAV(BaseNameScheme):
    rgx = re.compile(
        rf"^((?P<PREFIX>BC|Clamav)\.)?"
        rf"({PLATFORM_REGEXES}\.)?"
        rf"((?P<LABEL>\w+)\.)?"
        rf"(?P<NAME>.+?)?"
        rf"(\-(?P<VENDORID>[-0-9]+))?$"
    )


class DrWeb(BaseNameScheme):
    rgx = re.compile(
        rf"^({HEURISTICS}\s*(of)?\s*)?"
        rf"({EXPLOITS}\.)?"
        rf"{OSES.combine('PLATFORM', OSES, ARCHIVES, MACROS, LANGS)}?"
        rf"((\.|^)(?P<LABEL>[A-Za-z]*))?"
        rf"((\.|^)((?P<NAME>(?P<FAMILY>[A-Za-z][-\w\.]+?))((\.|$)(?P<VARIANT>[0-9]+))?))?"
        rf"(\.?(?P<SUFFIX>(origin|based)))?$"
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
        rf"^((?P<LABEL>[-\w]+)"
        rf"(\.|\/))?({PLATFORM_REGEXES}\.?)"
        rf"?((?P<NAME>[\.\-\w]+?)\.)?"
        rf"(?P<EXTRA>\w*)?$"
    )


class K7(BaseNameScheme):
    rgx = re.compile(rf"(?P<LABEL>[\w-]+)" rf"( \( (?P<EXTRA>[a-f0-9]+) \))?")


class Lionic(BaseNameScheme):
    rgx = re.compile(
        rf"^((?P<LABEL>\w+)\.)?"
        rf"({PLATFORM_REGEXES}\.)?"
        rf"((?P<NAME>[-\w\.]+))"
        rf"(\!\w.*)?"
    )


class NanoAV(BaseNameScheme):
    rgx = re.compile(
        rf"^((?P<CONFIDENCE>HEUR)\/)?"
        rf"((?P<PLATFORM1>\w+)\/)"
        rf"?((?P<LABEL>[\w\/]+))?\.?"
        rf"({PLATFORM_REGEXES}\.)?"
        rf"(?P<NAME>[\-\.\w]+(\.[A-Z]+)?)?$"
    )


class Qihoo360(BaseNameScheme):
    rgx = re.compile(rf"^({PLATFORM_REGEXES}\/)?((?P<LABEL>[^.]+)\.)((?P<NAME>\w+)\.)?(.*)$")


class QuickHeal(BaseNameScheme):
    rgx = re.compile(
        rf"^{EXPLOITS}?"
        rf"({PLATFORM_REGEXES})?"
        rf"((^|\.)(?P<LABEL>\w+))?"
        rf"(\/(?P<FAMILY>\w+))?"
        rf"((\.(?P<NAME>[-\w]+))"
        rf"(\.(?P<VARIANT>[\.\w]*))?)?$"
    )


class Rising(BaseNameScheme):
    rgx = re.compile(
        rf"^((?P<LABEL>\w+))?"
        r"(\.(?P<EXPLOIT>Exploit))?"
        r"(\.(?P<DDOS>DDoSer))?"
        # this hellscape is there to cover the 3 different formats rising can emit:
        # Label.Name/OS ...
        # Label.OS.Name ...
        # Label.Name.OS ..
        rf"(((((^|\/|\.)({PLATFORM_REGEXES})))|((\.|\/)(?P<FAMILY>[\-\w]+))))*"
        rf"((\#|\@|\!|\.)(?P<VARIANT>.*))$"
    )

    @property
    def heuristic(self):
        result = super().heuristic
        if result:
            return result
        cf = trx(self.values.get('CONFIDENCE'))
        lb = trx(self.values.get('LABEL'))
        if cf == trx('Heuristic'):
            # extract number from ET#96%
            return True
        elif cf == trx('Agent'):
            return True
        elif cf == "Heur" or lb == 'Heur' or lb == 'Generic':
            return True
        return False


class Virusdie(BaseNameScheme):
    rgx = re.compile(rf"((?P<LABEL>\w+)\.)?((?P<BEHAVIOR>\w+)\.)?(?P<EXTRA>\w*)")
