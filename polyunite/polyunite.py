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
        self.values = self.build_values(self.match)

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
            color = GROUP_COLORS.get(name, '')
            ss = ss[:idx] + color + mt + ('' if reset in ss[end:] else reset) + ss[end:]
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
        return any(
            HEURISTICS.find(value=f)
            for f in map(self.values.get, ('HEURISTICS', 'LABEL', 'FIELDS', 'NAME', 'FAMILY'))
            if f
        )

    @property
    def malice_unlikely(self) -> bool:
        return bool(
            self.match_raw(r'(\b|[^a-z])(not-a-virus|notavirus|eicar|test|testfile|testvirus)([^a-z]|\b)')
        )

    @property
    def name(self) -> str:
        return self.values.get('NAME') or self.values.get('FAMILY')

    @property
    def fullname(self) -> str:
        return self.values.get('FAMILY') or (
            '.'.join((self.values.get('NAME', ''), self.values.get('VARIANT', '')))
        ) or None

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
        values = {}
        if match:
            for k, v in match.groupdict().items():
                if not k.isupper():
                    raise ValueError("Must supply upper-cased group names")
                values[k] = v if v else ''
        return values


class Alibaba(BaseNameScheme):
    rgx = re.compile(
        rf"^((?P<LABEL>\w+):)?"
        rf"({PLATFORM_REGEXES}\/)?"
        rf"((?P<FAMILY>[^.]+))"
        rf"(\.(?P<VARIANT>.*))?$",
        flags=re.IGNORECASE
    )


class ClamAV(BaseNameScheme):
    rgx = re.compile(
        rf"^((?P<PREFIX>BC|Clamav)\.)?"
        rf"({PLATFORM_REGEXES}\.)?"
        rf"((?P<LABEL>\w+)\.)?"
        rf"(?P<FAMILY>.+?)?"
        rf"(\-(?P<VARIANT>[-0-9]+))?$"
    )


class DrWeb(BaseNameScheme):
    rgx = re.compile(
        rf"^({HEURISTICS}\s*(of)?\s*)?"
        rf"({EXPLOITS}\.)?"
        rf"{OSES.combine('PLATFORM', ARCHIVES, MACROS, LANGS)}?"
        rf"((\.|^)(?P<LABEL>[A-Za-z]*))?"
        rf"((\.|^)((?P<FAMILY>(?P<NAME>[A-Za-z][-\w\.]+?))((\.|$)(?P<VARIANT>[0-9]+))?))?"
        rf"(\.?(?P<SUFFIX>(origin|based)))?$"
    )


class Ikarus(BaseNameScheme):
    rgx = re.compile(
        r"^((?P<OBFUSCATION>Packed)\.)?"
        rf"(?P<HEURISTIC>[-\w+]+?\:)?"
        r"((?P<LABEL>[\w-]*?))?"
        rf"((^|[^\w]){PLATFORM_REGEXES})?"
        r"(\.(?P<FAMILY>..+))?$"
    )


class Jiangmin(BaseNameScheme):
    rgx = re.compile(
        rf"^((?P<LABEL>[-\w]+)"
        rf"(\.|\/))?({PLATFORM_REGEXES}\.?)"
        rf"?((?P<FAMILY>[\.\-\w]+?)\.)?"
        rf"(?P<VARIANT>\w*)?$"
    )


class K7(BaseNameScheme):
    rgx = re.compile(rf"(?P<LABEL>[\w-]+)" rf"( \( (?P<VARIANT>[a-f0-9]+) \))?")


class Lionic(BaseNameScheme):
    rgx = re.compile(
        rf"^((?P<LABEL>\w+)\.)?"
        rf"({PLATFORM_REGEXES}\.)?"
        rf"((?P<FAMILY>[-\w\.]+))"
        rf"(\!\w.*)?"
    )


class NanoAV(BaseNameScheme):
    rgx = re.compile(
        rf"^((?P<CONFIDENCE>HEUR)\/)?"
        rf"((?P<PLATFORM1>\w+)\/)"
        rf"?((?P<LABEL>[\w\/]+))?\.?"
        rf"({PLATFORM_REGEXES}\.)?"
        rf"(?P<FAMILY>[\-\.\w]+(\.[A-Z]+)?)?$"
    )


class Qihoo360(BaseNameScheme):
    rgx = re.compile(rf"^({PLATFORM_REGEXES}\/)?((?P<LABEL>[^.]+)\.)((?P<FAMILY>\w+)\.)?(.*)$")


class QuickHeal(BaseNameScheme):
    rgx = re.compile(
        r"^((?P<EXPLOIT>Exploit|Exp)\.)?"
        r"((\.|^)(?P<LABEL>[-\w]*?))?"
        rf"((\.|^)({PLATFORM_REGEXES}))?"
        r"((\.|\/)(?P<FAMILY>(((?P<NAME>[-\w]+))(\.(?P<VARIANT>\w+))?(\.(?P<SUFFIX>\w+))?)))?$"
        , re.IGNORECASE)


class Rising(BaseNameScheme):
    rgx = re.compile(
        rf"^((?P<LABEL>\w+))?"
        # this hellscape is there to cover the 3 different formats rising can emit:
        # Label.Name/OS ...
        # Label.OS.Name ...
        # Label.Name.OS ..
        rf"(((((^|\/|\.)({OSES.combine('PLATFORM', ARCHIVES, MACROS, LANGS, HEURISTICS)})))"
        r"|((\.|\/)(?P<FAMILY>[\-\w]+))|((\.|^)(?P<EXPLOIT>Exploit))|((\.|^)(?P<DDOS>DDoSer))))*"
        rf"((\#|\@|\!|\.)(?P<VARIANT>.*))$", re.IGNORECASE)

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
    rgx = re.compile(rf"((?P<LABEL>\w+)\.)?((?P<BEHAVIOR>\w+)\.)?(?P<VARIANT>\w*)")
