# enum identifiers are sourced from https://maecproject.github.io/documentation/maec5-docs/#introduction
import csv
import re
import string
from typing import Any, ClassVar, Dict, List, Optional, Type, Union

from polyunite.vocab import (
    ARCHIVES,
    EXPLOITS,
    LABELS,
    LANGS,
    MACROS,
    OSES,
    PLATFORM_REGEXES,
    VocabRegex,
)

SCHEMES = {}
DELNONALPHA = str.maketrans(
    string.ascii_uppercase, string.ascii_lowercase, string.punctuation + string.whitespace
)


def trx(ss: str):
    return ss.translate(DELNONALPHA)


class NamingScheme:
    match: Optional[re.Match]
    values: Dict[str, Any]
    rgx: re.Pattern

    @classmethod
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        name = trx(cls.__name__)
        SCHEMES[name] = cls

    def __init__(self, classification: str):
        normalized = classification
        self.match = self.rgx.match(normalized)
        self.values = {}
        if self.match:
            for k, v in self.match.groupdict().items():
                if not k.isupper():
                    raise ValueError("Must supply upper-cased group names")
                self.values[k] = v if v else ''

    @property
    def engine(self) -> str:
        return str(self.__class__.__name__)

    @property
    def heuristic(self):
        return None

    @property
    def name(self):
        return self.values.get('NAME')

    @property
    def operating_system(self):
        return OSES.find(self.values)

    @property
    def script(self):
        return LANGS.find(self.values)

    @property
    def label(self):
        return LABELS.find(self.values)

    def __repr__(self):
        fields = {f: getattr(self, f, None) for f in ('name', 'operating_system', 'script', 'label')}
        return '<{engine}.scheme({fields})>'.format(
            engine=self.engine, fields=", ".join([f'{f}={v}' for f, v in fields.items() if v])
        )

    def colorize(self):
        """Return a colorized classification string (works in Unix/VT200+ only)"""
        if not self.match:
            return None
        black = '\033[30m'
        red = '\033[31m'
        green = '\033[32m'
        yellow = '\033[33m'
        blue = '\033[34m'
        magenta = '\033[35m'
        cyan = '\033[36m'
        white = '\033[37m'
        underline = '\033[4m'
        reset = '\033[0m'
        gr_color = {
            'NAME': red,
            'PLATFORM': underline,
            'LABEL': yellow,
            'VENDORID': blue,
            'PREFIX': cyan,
            'CONFIDENCE': underline,
            'OPERATINGSYSTEM': underline + magenta,
            'FAMILY': red,
            'VARIANT': green,
            'OBFUSCATION': black,
            'EXTRA': white,
            'LANGS': red,
            'EXPLOIT': white,
            'BEHAVIOR': white,
        }
        ss = self.match.string
        for name, mt in self.match.groupdict().items():
            if name not in gr_color or not mt:
                continue
            start = self.match.start(name)
            idx = ss.find(mt, start)
            end = idx + len(mt)
            ss = ss[:idx] + gr_color[name] + mt + reset + ss[end:]
        return ss


class Alibaba(NamingScheme):
    rgx = re.compile(
        rf"^((?P<LABEL>\w+):)?"
        rf"({PLATFORM_REGEXES}\/)?"
        rf"((?P<NAME>[^.]+))"
        rf"(\.(?P<VENDORID>.*))?$",
        flags=re.IGNORECASE
    )


class ClamAV(NamingScheme):
    rgx = re.compile(
        rf"^((?P<PREFIX>BC|Clamav)\.)?"
        rf"({PLATFORM_REGEXES}\.)?"
        rf"((?P<LABEL>\w+)\.)?"
        rf"(?P<NAME>.+?)?"
        rf"(\-(?P<VENDORID>[-0-9]+))?$"
    )


class DrWeb(NamingScheme):
    rgx = re.compile(
        rf"^((?P<CONFIDENCE>probably|modification)\s*(of)?\s*)?"
        rf"({EXPLOITS}\.)?"
        rf"{PLATFORM_REGEXES}?"
        rf"((\.|\b)(?P<LABEL>[A-Za-z]*))?"
        rf"((\.|\b)((?P<NAME>(?P<FAMILY>[A-Za-z][-\w\.]+?))((\.|$)(?P<VARIANT>[0-9]+))?))?"
        rf"(\.?(?P<SUFFIX>(origin|based)))?$"
    )


class Ikarus(NamingScheme):
    rgx = re.compile(
        r"^((?P<OBFUSCATION>Packed)\.)?"
        r"((?P<CONFIDENCE>not\-a\-virus|HEUR)(\.|\:))?"
        r"((?P<LABEL>[\w-]*?))?"
        rf"((^|[^\w]){PLATFORM_REGEXES})?"
        r"(\.(?P<NAME>..+))?$"
    )


class Jiangmin(NamingScheme):
    rgx = re.compile(
        rf"^((?P<LABEL>[-\w]+)"
        rf"(\.|\/))?({PLATFORM_REGEXES}\.?)"
        rf"?((?P<NAME>[\.\-\w]+?)\.)?"
        rf"(?P<EXTRA>\w*)?$"
    )


class K7(NamingScheme):
    rgx = re.compile(rf"(?P<LABEL>[\w-]+)" rf"( \( (?P<EXTRA>[a-f0-9]+) \))?")


class Lionic(NamingScheme):
    rgx = re.compile(
        rf"^((?P<LABEL>\w+)\.)?"
        rf"({PLATFORM_REGEXES}\.)?"
        rf"((?P<NAME>[-\w\.]+))"
        rf"(\!\w.*)?"
    )


class NanoAV(NamingScheme):
    rgx = re.compile(
        rf"^((?P<CONFIDENCE>HEUR)\/)?"
        rf"((?P<PLATFORM1>\w+)\/)"
        rf"?((?P<LABEL>[\w\/]+))?\.?"
        rf"({PLATFORM_REGEXES}\.)?"
        rf"(?P<NAME>[\-\.\w]+(\.[A-Z]+)?)?$"
    )


class Qihoo360(NamingScheme):
    rgx = re.compile(rf"^({PLATFORM_REGEXES}\/)?((?P<LABEL>[^.]+)\.)((?P<NAME>\w+)\.)?(.*)$")


class QuickHeal(NamingScheme):
    rgx = re.compile(
        rf"^{EXPLOITS}?"
        rf"({PLATFORM_REGEXES})?"
        rf"((^|\.)(?P<LABEL>\w+))?"
        rf"(\/(?P<FAMILY>\w+))?"
        rf"((\.(?P<NAME>[-\w]+))"
        rf"(\.(?P<VARIANT>[\.\w]*))?)?$"
    )


class Rising(NamingScheme):
    rgx = re.compile(
        rf"^((?P<LABEL>\w+))?"
        rf"(?=.).((?P<FAMILY>[\/\w]*?)\.)?"
        rf"(?P<NAME>[^!\s\/\.]+)?"
        rf"(\.(?P<VARIANT>\w+))?"
        rf"(/{PLATFORM_REGEXES})?"
        rf"(\!(?P<EXTRA>.*))?$"
    )


class Virusdie(NamingScheme):
    rgx = re.compile(rf"((?P<LABEL>\w+)\.)?((?P<BEHAVIOR>\w+)\.)?(?P<EXTRA>\w*)")


def seen(f):
    with open(f, newline='') as csvfile:
        yield from csv.reader(csvfile)


for name, family in seen('engine_families.csv'):
    engine = trx(name)
    if engine in SCHEMES:
        # print("ENGINE: %s = %s" % (engine, NamingScheme._engines[NamingScheme.to_engine(engine)].rgx))
        res = SCHEMES[engine](family)
        print(res.colorize())
        # print(res)
